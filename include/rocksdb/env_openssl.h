//  copyright (c) 2011-present, Facebook, Inc.  All rights reserved.
//  This source code is licensed under both the GPLv2 (found in the
//  COPYING file in the root directory) and Apache 2.0 License
//  (found in the LICENSE.Apache file in the root directory).

//
// env_encryption.cc copied to this file then modified.

#pragma once

#ifdef ROCKSDB_OPENSSL_AES_CTR
#ifndef ROCKSDB_LITE

#include <memory>
#include <map>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "port/port.h"
#include "rocksdb/env.h"
#include "rocksdb/env_encryption.h"
#include "rocksdb/slice.h"

namespace ROCKSDB_NAMESPACE {

struct ShaDescription {
  uint8_t desc[EVP_MAX_MD_SIZE];
  bool valid;

  ShaDescription() : valid(false) { memset(desc, 0, EVP_MAX_MD_SIZE); }

  ShaDescription(const ShaDescription& rhs) { *this = rhs; }

  ShaDescription& operator=(const ShaDescription& rhs) {
    memcpy(desc, rhs.desc, sizeof(desc));
    valid = rhs.valid;
    return *this;
  }

  ShaDescription(uint8_t* desc_in, size_t desc_len) : valid(false) {
    memset(desc, 0, EVP_MAX_MD_SIZE);
    if (desc_len <= EVP_MAX_MD_SIZE) {
      memcpy(desc, desc_in, desc_len);
      valid = true;
    }
  }

  ShaDescription(const std::string& key_desc_str);

  // see AesCtrKey destructor below.  This data is not really
  //  essential to clear, but trying to set pattern for future work.
  // goal is to explicitly remove desc from memory once no longer needed
  ~ShaDescription() {
    memset(desc, 0, EVP_MAX_MD_SIZE);
    valid = false;
  }

  bool operator<(const ShaDescription& rhs) const {
    return memcmp(desc, rhs.desc, EVP_MAX_MD_SIZE) < 0;
  }

  bool operator==(const ShaDescription& rhs) const {
    return 0 == memcmp(desc, rhs.desc, EVP_MAX_MD_SIZE) && valid == rhs.valid;
  }

  bool IsValid() const { return valid; }

  std::string ToString(size_t byte_count = 20) const {
    if (IsValid()) {
      if (EVP_MAX_MD_SIZE < byte_count) {
        byte_count = EVP_MAX_MD_SIZE;
      }
      rocksdb::Slice to_hex((const char *)desc, byte_count);
      return to_hex.ToString(true);
    } else {
      return std::string();
    }
  }
};

struct AesCtrKey {
  uint8_t key[EVP_MAX_KEY_LENGTH];
  bool valid;

  AesCtrKey() : valid(false) { memset(key, 0, EVP_MAX_KEY_LENGTH); }

  AesCtrKey(const uint8_t* key_in, size_t key_len) : valid(false) {
    memset(key, 0, EVP_MAX_KEY_LENGTH);
    if (key_len <= EVP_MAX_KEY_LENGTH) {
      memcpy(key, key_in, key_len);
      valid = true;
    } else {
      valid = false;
    }
  }

  AesCtrKey(const std::string& key_str);

  // see Writing Solid Code, 2nd edition
  //   Chapter 9, page 321, Managing Secrets in Memory ... bullet 4 "Scrub the
  //   memory"
  // Not saying this is essential or effective in initial implementation since
  // current
  //  usage model loads all keys at start and only deletes them at shutdown. But
  //  does establish presidence.
  // goal is to explicitly remove key from memory once no longer needed
  ~AesCtrKey() {
    memset(key, 0, EVP_MAX_KEY_LENGTH);
    valid = false;
  }

  bool operator==(const AesCtrKey& rhs) const {
    return (0 == memcmp(key, rhs.key, EVP_MAX_KEY_LENGTH)) &&
           (valid == rhs.valid);
  }

  bool IsValid() const { return valid; }

  std::string ToString(size_t byte_count = 32) const {
    if (IsValid()) {
      if (EVP_MAX_KEY_LENGTH < byte_count) {
        byte_count = EVP_MAX_KEY_LENGTH;
      }
      rocksdb::Slice to_hex((const char *)key, byte_count);
      return to_hex.ToString(true);
    } else {
      return std::string();
    }
  }
};


class EncryptionProviderOpenSSL : public EncryptionProvider {
 public:
  EncryptionProviderOpenSSL() = delete;

  EncryptionProviderOpenSSL(const EncryptionProviderOpenSSL&&) = delete;

  EncryptionProviderOpenSSL(const ShaDescription& key_desc_in,
                          const AesCtrKey& key_in)
      : encrypt_read_({{key_desc_in, key_in}}), encrypt_write_({key_desc_in, key_in}) {
    valid_ = key_desc_in.IsValid() && key_in.IsValid();
  }

  EncryptionProviderOpenSSL(const std::string& key_desc_str,
                          const uint8_t unformatted_key[], int bytes)
      : valid_(false) {
    ShaDescription desc(key_desc_str);
    AesCtrKey aes(unformatted_key, bytes);

    encrypt_write_ = std::pair<ShaDescription, AesCtrKey>(desc, aes);
    encrypt_read_.insert(std::pair<ShaDescription, AesCtrKey>(desc, aes));
    valid_ = desc.IsValid() && aes.IsValid();
  }

  const char * Name() const override {return "EncryptionProviderOpenSSL";}

  size_t GetPrefixLength() const override;

  Status CreateNewPrefix(const std::string& /*fname*/, char* prefix,
                         size_t prefixLength) const override;

  Status AddCipher(const std::string& descriptor, const char* cipher,
                           size_t len, bool for_write) override;

  Status CreateCipherStream(
      const std::string& /*fname*/, const EnvOptions& /*options*/,
      Slice& /*prefix*/,
      std::unique_ptr<BlockAccessCipherStream>* /*result*/) override;

  bool IsValid() const { return valid_; };

  using WriteKey = std::pair<ShaDescription, AesCtrKey>;
  using ReadKeys = std::map<ShaDescription, AesCtrKey>;

 protected:
  ReadKeys encrypt_read_;
  WriteKey encrypt_write_;
  mutable port::RWMutex key_lock_;
  bool valid_;
};

}  // namespace ROCKSDB_NAMESPACE

#endif  // ROCKSDB_LITE

#endif  // ROCKSDB_OPENSSL_AES_CTR
