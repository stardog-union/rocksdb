//  Copyright (c) 2011-present, Facebook, Inc.  All rights reserved.
//  This source code is licensed under both the GPLv2 (found in the
//  COPYING file in the root directory) and Apache 2.0 License
//  (found in the LICENSE.Apache file in the root directory).

//
// env_encryption.cc copied to this file then modified.

#ifndef ROCKSDB_LITE

#include <algorithm>
#include <cctype>
#include <iostream>
#include <byteswap.h>

#include "openssl/rand.h"
#include "openssl/aes.h"

#include "rocksdb/env_encrypt_2.h"
#include "util/aligned_buffer.h"
#include "util/coding.h"
#include "util/random.h"

#endif

namespace rocksdb {

// following define block from page 70:
//  https://www.intel.com/content/dam/doc/white-paper/advanced-encryption-standard-new-instructions-set-paper.pdf
#if !defined (ALIGN16)
# if defined (__GNUC__)
# define ALIGN16 __attribute__ ( (aligned (16)))
# else
# define ALIGN16 __declspec (align (16))
# endif
#endif

#ifndef ROCKSDB_LITE

typedef union {
  uint64_t nums[2];
  uint8_t bytes[AES_BLOCK_SIZE];
} AesAlignedBlock_t;

Status AESBlockAccessCipherStream::EncryptBlock(uint64_t blockIndex, char *data, char* /*scratch*/) {
  assert(AES_BLOCK_SIZE==16);        // AES_BLOCK_SIZE assumed to be 16
  assert(sizeof(AesAlignedBlock_t)==AES_BLOCK_SIZE);

  Status status;
  ALIGN16 AesAlignedBlock_t block_in, block_out, iv;
  int out_len=0, in_len={AES_BLOCK_SIZE}, ret_val;

  std::unique_ptr<EVP_CIPHER_CTX, void(*)(EVP_CIPHER_CTX *)> context(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
  iv.nums[0]=0;
  iv.nums[1]=0;
  ret_val = EVP_EncryptInit_ex(context.get(), EVP_aes_256_ctr(), nullptr, key_.key, iv.bytes);
  memcpy(block_in.bytes, nonce_, AES_BLOCK_SIZE/2);
  EncodeFixed64((char*)&block_in.bytes[AES_BLOCK_SIZE/2], blockIndex); // this will be little endian
  ret_val = EVP_EncryptUpdate(context.get(), block_out.bytes, &out_len, block_in.bytes, in_len);
  (void)ret_val;

  // XOR data with ciphertext.
  for (size_t idx = 0; idx < AES_BLOCK_SIZE; ++idx) {
    data[idx] = data[idx] ^ block_out.bytes[idx];
  }
  return status;
}

Status AESBlockAccessCipherStream::DecryptBlock(uint64_t blockIndex, char *data, char* scratch) {
  return EncryptBlock(blockIndex, data, scratch);
}

// Returns an Env that encrypts data when stored on disk and decrypts data when
// read from disk.
Env* NewEncryptedEnv2(Env* base_env,
                      std::map<Sha1Description_t,std::shared_ptr<EncryptionProvider>> encrypt_read,
                      std::pair<Sha1Description_t,std::shared_ptr<EncryptionProvider>> encrypt_write) {
  return new EncryptedEnv2(base_env, encrypt_read, encrypt_write);
}


  // NewSequentialFile opens a file for sequential reading.
  Status EncryptedEnv2::NewSequentialFile(const std::string& fname,
                                   std::unique_ptr<SequentialFile>* result,
                                   const EnvOptions& options) {
    result->reset();
    if (options.use_mmap_reads) {
      return Status::InvalidArgument();
    }

    // Open file using underlying Env implementation
    std::unique_ptr<SequentialFile> underlying;
    auto status = EnvWrapper::NewSequentialFile(fname, &underlying, options);
    if (status.ok()) {
      std::shared_ptr<EncryptionProvider> provider;
      std::unique_ptr<BlockAccessCipherStream> stream;
      status=ReadSeqEncryptionPrefix<SequentialFile>(underlying.get(), provider, stream);

      if (status.ok()) {
        if (provider) {
          (*result) = std::unique_ptr<SequentialFile>(
            new EncryptedSequentialFile(underlying.release(),
                                        stream.release(),
                                        provider->GetPrefixLength()));

        } else {
          // normal file, not encrypted
          // sequential file might not allow backing up to begining, close and reopen
          underlying.reset(nullptr);
          status = EnvWrapper::NewSequentialFile(fname, result, options);
        }
      }
    }

    return status;
  }

  // NewRandomAccessFile opens a file for random read access.
  Status EncryptedEnv2::NewRandomAccessFile(const std::string& fname,
                                     std::unique_ptr<RandomAccessFile>* result,
                                     const EnvOptions& options) {
    result->reset();
    if (options.use_mmap_reads) {
      return Status::InvalidArgument();
    }

    // Open file using underlying Env implementation
    std::unique_ptr<RandomAccessFile> underlying;
    auto status = EnvWrapper::NewRandomAccessFile(fname, &underlying, options);
    if (status.ok()) {
      std::shared_ptr<EncryptionProvider> provider;
      std::unique_ptr<BlockAccessCipherStream> stream;
      status=ReadRandEncryptionPrefix<RandomAccessFile>(underlying.get(), provider, stream);

      if (status.ok()) {
        if (provider) {
          (*result) = std::unique_ptr<RandomAccessFile>(
            new EncryptedRandomAccessFile(underlying.release(),
                                          stream.release(),
                                          provider->GetPrefixLength()));

        } else {
          // normal file, not encrypted
          (*result).reset(underlying.release());
        }
      }
    }
    return status;
  }

  // NewWritableFile opens a file for sequential writing.
  Status EncryptedEnv2::NewWritableFile(const std::string& fname,
                                 std::unique_ptr<WritableFile>* result,
                                 const EnvOptions& options) {
    Status status;
    result->reset();

    if (!options.use_mmap_writes) {
      // Open file using underlying Env implementation
      std::unique_ptr<WritableFile> underlying;
      status = EnvWrapper::NewWritableFile(fname, &underlying, options);

      if (status.ok()) {
        if (IsWriteEncrypted()) {
          std::unique_ptr<BlockAccessCipherStream> stream;

          status = WriteSeqEncryptionPrefix(underlying.get(), stream);

          if (status.ok()) {
            (*result) = std::unique_ptr<WritableFile>(
              new EncryptedWritableFile(underlying.release(), stream.release(),
                                        encrypt_write_.second->GetPrefixLength()));
          }
        } else {
          (*result).reset(underlying.release());
        }
      }
    } else {
      status = Status::InvalidArgument();
    }

    return status;
  }

  // Create an object that writes to a new file with the specified
  // name.  Deletes any existing file with the same name and creates a
  // new file.  On success, stores a pointer to the new file in
  // *result and returns OK.  On failure stores nullptr in *result and
  // returns non-OK.
  //
  // The returned file will only be accessed by one thread at a time.
  Status EncryptedEnv2::ReopenWritableFile(const std::string& fname,
                                    std::unique_ptr<WritableFile>* result,
                                    const EnvOptions& options) {
    Status status;
    result->reset();

    if (!options.use_mmap_writes) {
      // Open file using underlying Env implementation
      std::unique_ptr<WritableFile> underlying;
      status = EnvWrapper::ReopenWritableFile(fname, &underlying, options);

      if (status.ok()) {
        if (IsWriteEncrypted()) {
          std::unique_ptr<BlockAccessCipherStream> stream;

          status = WriteSeqEncryptionPrefix(underlying.get(), stream);

          if (status.ok()) {
            (*result) = std::unique_ptr<WritableFile>(
              new EncryptedWritableFile(underlying.release(), stream.release(),
                                        encrypt_write_.second->GetPrefixLength()));
          }
        } else {
          (*result).reset(underlying.release());
        }
      }
    } else {
      status = Status::InvalidArgument();
    }

    return status;
  }


  // Reuse an existing file by renaming it and opening it as writable.
  Status EncryptedEnv2::ReuseWritableFile(const std::string& fname,
                                   const std::string& old_fname,
                                   std::unique_ptr<WritableFile>* result,
                                   const EnvOptions& options) {
    Status status;
    result->reset();

    if (!options.use_mmap_writes) {
      // Open file using underlying Env implementation
      std::unique_ptr<WritableFile> underlying;
      status = EnvWrapper::ReuseWritableFile(fname, old_fname, &underlying, options);

      if (status.ok()) {
        if (IsWriteEncrypted()) {
          std::unique_ptr<BlockAccessCipherStream> stream;

          status = WriteSeqEncryptionPrefix(underlying.get(), stream);

          if (status.ok()) {
            (*result) = std::unique_ptr<WritableFile>(
              new EncryptedWritableFile(underlying.release(), stream.release(),
                                        encrypt_write_.second->GetPrefixLength()));
          }
        } else {
          (*result).reset(underlying.release());
        }
      }
    } else {
      status = Status::InvalidArgument();
    }

    return status;
  }


  // Open `fname` for random read and write, if file doesn't exist the file
  // will be created.  On success, stores a pointer to the new file in
  // *result and returns OK.  On failure returns non-OK.
  //
  // The returned file will only be accessed by one thread at a time.
  Status EncryptedEnv2::NewRandomRWFile(const std::string& fname,
                                 std::unique_ptr<RandomRWFile>* result,
                                 const EnvOptions& options) {
    Status status;
    result->reset();

    // Check file exists
    bool isNewFile = !FileExists(fname).ok();

    if (!options.use_mmap_writes && !options.use_mmap_reads) {
      // Open file using underlying Env implementation
      std::unique_ptr<RandomRWFile> underlying;
      status = EnvWrapper::NewRandomRWFile(fname, &underlying, options);

      if (status.ok()) {
        std::shared_ptr<EncryptionProvider> provider;
        std::unique_ptr<BlockAccessCipherStream> stream;

        if (!isNewFile) {
          // file exists, get existing crypto info
          status = ReadRandEncryptionPrefix<RandomRWFile>(underlying.get(), provider, stream);

        } else {
          // new file
          if (IsWriteEncrypted()) {
            status = WriteRandEncryptionPrefix(underlying.get(), stream);
            provider = encrypt_write_.second;
          }
        }

        // establish encrypt or not, finalize file object
        if (status.ok()) {
          if (provider) {
            (*result) = std::unique_ptr<RandomRWFile>(
              new EncryptedRandomRWFile(underlying.release(), stream.release(),
                                        provider->GetPrefixLength()));
          } else {
            (*result).reset(underlying.release());
          }
        }
      }
    } else {
      status = Status::InvalidArgument();
    }

    return status;
  }

  // Store in *result the attributes of the children of the specified directory.
  // In case the implementation lists the directory prior to iterating the files
  // and files are concurrently deleted, the deleted files will be omitted from
  // result.
  // The name attributes are relative to "dir".
  // Original contents of *results are dropped.
  // Returns OK if "dir" exists and "*result" contains its children.
  //         NotFound if "dir" does not exist, the calling process does not have
  //                  permission to access "dir", or if "dir" is invalid.
  //         IOError if an IO Error was encountered
  Status EncryptedEnv2::GetChildrenFileAttributes(const std::string& dir, std::vector<FileAttributes>* result) {
    auto status = EnvWrapper::GetChildrenFileAttributes(dir, result);
    if (status.ok()) {
      // this is slightly expensive, but fortunately not used heavily
      std::shared_ptr<EncryptionProvider> provider;

      for (auto it = std::begin(*result); it!=std::end(*result); ++it) {
        status = GetEncryptionProvider(it->name, provider);

        if (status.ok() && provider) {
          size_t prefixLength = provider->GetPrefixLength();

          if (prefixLength <= it->size_bytes)
            it->size_bytes -= prefixLength;
        }
      }
    }

    return status;
 }

  // Store the size of fname in *file_size.
  Status EncryptedEnv2::GetFileSize(const std::string& fname, uint64_t* file_size) {
    Status status;
    status = EnvWrapper::GetFileSize(fname, file_size);

    if (status.ok()) {
      // this is slightly expensive, but fortunately not used heavily
      std::shared_ptr<EncryptionProvider> provider;
      status = GetEncryptionProvider(fname, provider);
      if (status.ok() && provider) {
        size_t prefixLength = provider->GetPrefixLength();
        if (prefixLength <= *file_size)
          *file_size -= prefixLength;
      }
    }

    return status;
  }

  Status EncryptedEnv2::GetEncryptionProvider(const std::string& fname, std::shared_ptr<EncryptionProvider> & provider) {
    std::unique_ptr<SequentialFile> underlying;
    EnvOptions options;
    Status status;

    provider.reset();
    status = Env::Default()->NewSequentialFile(fname, &underlying, options);

    if (status.ok()) {
      std::unique_ptr<BlockAccessCipherStream> stream;
      status = EncryptedEnv2::ReadSeqEncryptionPrefix(underlying.get(), provider, stream);
    }

    return status;
  }

#endif // ROCKSDB_LITE

}  // namespace rocksdb
