//  Copyright (c) 2011-present, Facebook, Inc.  All rights reserved.
//  This source code is licensed under both the GPLv2 (found in the
//  COPYING file in the root directory) and Apache 2.0 License
//  (found in the LICENSE.Apache file in the root directory).

//
// env_encryption.cc copied to this file then modified.

#ifdef ROCKSDB_OPENSSL_AES_CTR
#ifndef ROCKSDB_LITE

#include "rocksdb/env_openssl.h"

#include <algorithm>
#include <cctype>
#include <iostream>
#include <mutex>

#include "env/env_openssl_impl.h"
#include "monitoring/perf_context_imp.h"
#include "port/port.h"
#include "util/aligned_buffer.h"
#include "util/coding.h"
#include "util/library_loader.h"
#include "util/mutexlock.h"
#include "util/random.h"

namespace ROCKSDB_NAMESPACE {

static std::once_flag crypto_loaded;
static std::shared_ptr<UnixLibCrypto> crypto_shared;

std::shared_ptr<UnixLibCrypto> GetCrypto() {
  std::call_once(crypto_loaded,
                 []() { crypto_shared = std::make_shared<UnixLibCrypto>(); });
  return crypto_shared;
}

// reuse cipher context between calls to Encrypt & Decrypt
static void do_nothing(EVP_CIPHER_CTX*){};
thread_local static std::unique_ptr<EVP_CIPHER_CTX, void (*)(EVP_CIPHER_CTX*)>
    aes_context(nullptr, &do_nothing);

ShaDescription::ShaDescription(const std::string& key_desc_str) {
  GetCrypto();  // ensure libcryto available
  bool good = {true};
  int ret_val;
  unsigned len;

  memset(desc, 0, EVP_MAX_MD_SIZE);
  if (0 != key_desc_str.length() && crypto_shared->IsValid()) {
    std::unique_ptr<EVP_MD_CTX, void (*)(EVP_MD_CTX*)> context(
        crypto_shared->EVP_MD_CTX_new(),
        crypto_shared->EVP_MD_CTX_free_ptr());

    ret_val = crypto_shared->EVP_DigestInit_ex(
        context.get(), crypto_shared->EVP_sha1(), nullptr);
    good = (1 == ret_val);
    if (good) {
      ret_val = crypto_shared->EVP_DigestUpdate(
          context.get(), key_desc_str.c_str(), key_desc_str.length());
      good = (1 == ret_val);
    }

    if (good) {
      ret_val =
          crypto_shared->EVP_DigestFinal_ex(context.get(), desc, &len);
      good = (1 == ret_val);
    }
  } else {
    good = false;
  }

  valid = good;
}

AesCtrKey::AesCtrKey(const std::string& key_str) : valid(false) {
  GetCrypto();  // ensure libcryto available
  memset(key, 0, EVP_MAX_KEY_LENGTH);

  // simple parse:  must be 64 characters long and hexadecimal values
  if (64 == key_str.length()) {
    auto bad_pos = key_str.find_first_not_of("abcdefABCDEF0123456789");
    if (std::string::npos == bad_pos) {
      for (size_t idx = 0, idx2 = 0; idx < key_str.length(); idx += 2, ++idx2) {
        std::string hex_string(key_str.substr(idx, 2));
        key[idx2] = std::stoul(hex_string, 0, 16);
      }
      valid = true;
    }
  }
}


void AESBlockAccessCipherStream::BigEndianAdd128(uint8_t* buf,
                                                 uint64_t value) {
  uint8_t *sum, *addend, *carry, pre, post;

  sum = buf + 15;

  if (port::kLittleEndian) {
    addend = (uint8_t*)&value;
  } else {
    addend = (uint8_t*)&value + 7;
  }

  // future:  big endian could be written as uint64_t add
  for (int loop = 0; loop < 8 && value; ++loop) {
    pre = *sum;
    *sum += *addend;
    post = *sum;
    --sum;
    value >>= 8;

    carry = sum;
    // carry?
    while (post < pre && buf <= carry) {
      pre = *carry;
      *carry += 1;
      post = *carry;
      --carry;
    }
  }  // for
}

// "data" is assumed to be aligned at AES_BLOCK_SIZE or greater
Status AESBlockAccessCipherStream::Encrypt(uint64_t file_offset, char* data,
                                           size_t data_size) {
  Status status;
  if (0 < data_size) {
    if (crypto_shared->IsValid()) {
      int ret_val, out_len;
      ALIGN16 uint8_t iv[AES_BLOCK_SIZE];
      uint64_t block_index = file_offset / BlockSize();
      uint64_t remainder = file_offset % BlockSize();

      // make a context once per thread
      if (!aes_context) {
        aes_context =
            std::unique_ptr<EVP_CIPHER_CTX, void (*)(EVP_CIPHER_CTX*)>(
                crypto_shared->EVP_CIPHER_CTX_new(),
                crypto_shared->EVP_CIPHER_CTX_free_ptr());
      }

      memcpy(iv, nonce_, AES_BLOCK_SIZE);
      BigEndianAdd128(iv, block_index);
      ret_val = crypto_shared->EVP_EncryptInit_ex(
          aes_context.get(), crypto_shared->EVP_aes_256_ctr(), nullptr,
          key_.key, iv);
      if (1 != ret_val) {
        status = Status::InvalidArgument("EVP_EncryptInit_ex failed.");
      }

      // if start not aligned to block size, do partial
      if (1 == ret_val && 0 != remainder) {
        size_t partial_len;
        ALIGN16 uint8_t partial[AES_BLOCK_SIZE];
        memset(partial, 0, sizeof(partial));

        partial_len = AES_BLOCK_SIZE - remainder;
        if (data_size < partial_len) {
          partial_len = data_size;
        }
        out_len = 0;
        ret_val = crypto_shared->EVP_EncryptUpdate(
            aes_context.get(), (unsigned char*)partial, &out_len,
            (unsigned char*)partial, (int)sizeof(partial));

        if (1 == ret_val && out_len == AES_BLOCK_SIZE) {
          // xor against real data
          for (size_t pos = 0; pos < partial_len; ++pos) {
            *(data + pos) ^= partial[remainder + pos];
          }
        } else {
          status = Status::InvalidArgument("EVP_EncryptUpdate failed: ",
                                           (int)data_size == AES_BLOCK_SIZE
                                           ? "bad return value"
                                           : "output length short");
        }

        data += partial_len;
        BigEndianAdd128(iv, 1);
        if (partial_len < data_size) {
          data_size -= partial_len;
        } else {
          data_size = 0;
        }
      }

      // do remaining data: starts on boundry but may or may not end on one.
      if (1 == ret_val && data_size) {
        out_len = 0;
        ret_val = crypto_shared->EVP_EncryptUpdate(
            aes_context.get(), (unsigned char*)data, &out_len,
            (unsigned char*)data, (int)data_size);
        if (1 != ret_val || out_len != (int)data_size) {
          status = Status::InvalidArgument("EVP_EncryptUpdate failed: ",
                                           (int)data_size == out_len
                                               ? "bad return value"
                                               : "output length short");
        }
      }

      // clean up
      if (1 == ret_val) {
        // this is a soft reset of aes_context per man pages
        uint8_t temp_buf[AES_BLOCK_SIZE];
        out_len = 0;
        ret_val = crypto_shared->EVP_EncryptFinal_ex(aes_context.get(),
                                                     temp_buf, &out_len);

        if (1 != ret_val || 0 != out_len) {
          status = Status::InvalidArgument(
              "EVP_EncryptFinal_ex failed: ",
              (1 != ret_val) ? "bad return value" : "output length short");
        }
      }
    } else {
      status = Status::NotSupported(
          "libcrypto not available for encryption/decryption.");
    }
  }

  return status;
}

// Decrypt one or more (partial) blocks of data at the file offset.
//  Length of data is given in data_size.
//  CTR Encrypt and Decrypt are synonyms.  Using Encrypt calls here to reduce
//   count of symbols loaded from libcrypto.
Status AESBlockAccessCipherStream::Decrypt(uint64_t file_offset, char* data,
                                           size_t data_size) {

  return Encrypt(file_offset, data, data_size);
}

Status EncryptionProviderOpenSSL::CreateNewPrefix(const std::string& /*fname*/,
                                                char* prefix,
                                                size_t prefixLength) const {
  GetCrypto();  // ensure libcryto available
  Status s;
  if (crypto_shared->IsValid()) {
    if (sizeof(PrefixVersion0) + sizeof(OpenSSLEncryptMarker) <= prefixLength) {
      int ret_val;

      memcpy(prefix, kOpenSSLEncryptMarker, sizeof(kOpenSSLEncryptMarker));
      *(prefix + sizeof(kOpenSSLEncryptMarker)) = kOpenSSLEncryptCodeVersion1;

      PrefixVersion0* pf = {(PrefixVersion0*)(prefix + sizeof(OpenSSLEncryptMarker))};
      memcpy(pf->key_description_, encrypt_write_.first.desc, sizeof(encrypt_write_.first.desc));
      ret_val = crypto_shared->RAND_bytes((unsigned char*)&pf->nonce_,
                                                   AES_BLOCK_SIZE);
      if (1 != ret_val) {
        s = Status::NotSupported("RAND_bytes failed");
      }
    } else {
      s = Status::NotSupported("Prefix size needs to be 28 or more");
    }
  } else {
    s = Status::NotSupported("RAND_bytes() from libcrypto not available.");
  }

  return s;
}

size_t EncryptionProviderOpenSSL::GetPrefixLength() const {
  return kDefaultPageSize;  // for direct io alignment
}

Status EncryptionProviderOpenSSL::CreateCipherStream(
    const std::string& /*fname*/, const EnvOptions& /*options*/,
    Slice& prefix,
    std::unique_ptr<BlockAccessCipherStream>* result) {
  Status stat;

  // for direct io, prefix size matched to one page to keep file contents aligned.
  if (kDefaultPageSize == prefix.size()) {
    if (prefix.starts_with(kOpenSSLEncryptMarker)) {
        uint8_t code_version = (uint8_t)prefix[sizeof(kOpenSSLEncryptMarker)];
        switch (code_version) {
          case kOpenSSLEncryptCodeVersion1: {
            PrefixVersion0 * prefix_struct = (PrefixVersion0 *)(prefix.data() + sizeof(OpenSSLEncryptMarker));
            ShaDescription desc(prefix_struct->key_description_, sizeof(PrefixVersion0::key_description_));
            auto read_key = encrypt_read_.find(desc);

            if (encrypt_read_.end() != read_key) {
              (*result).reset(new AESBlockAccessCipherStream(read_key->second, code_version, prefix_struct->nonce_));
            } else {
              stat = Status::NotSupported("File requires unknown encryption key");
            }
            break;
          }

          default: {
            stat = Status::NotSupported("Unknown code version for this encryption provider");
            break;
          }
        }
      } else {
        stat = Status::NotSupported("Prefix marker wrong for this encryption provider");
      }
  } else {
    stat = Status::NotSupported("Prefix wrong size for this encryption provider");
  }

  return stat;
}

}  // namespace ROCKSDB_NAMESPACE

#endif  // ROCKSDB_LITE
#endif  // ROCKSDB_OPENSSL_AES_CTR
