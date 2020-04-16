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

#include "openssl/rand.h"
#include "openssl/aes.h"

#include "rocksdb/env_encryption.h"
#include "util/aligned_buffer.h"
#include "util/coding.h"
#include "util/random.h"

#endif

namespace rocksdb {

#ifndef ROCKSDB_LITE

typedef uint8_t Sha1Description_t[20];
typedef char EncryptMarker_t[8];
static EncryptMarker_t Marker = "Encrypt";

// long term:  code_version could be used in a switch statement or factory parameter
// version 0 is 12 byte sha1 description hash, 128 bit (16 byte) nounce (assumed to be packed/byte aligned)
typedef struct {
  Sha1Description_t key_description_;
  uint8_t nonce_[AES_BLOCK_SIZE/2];      // block size is 16
} Prefix0_t;


class AESBlockAccessCipherStream : public BlockAccessCipherStream {
    public:
  AESBlockAccessCipherStream(const AES_KEY & key, uint8_t code_version, uint8_t nonce[])
    : key_(key), code_version_(code_version) {
    memcpy(&nonce_, nonce, sizeof(AES_BLOCK_SIZE/2));
  }

  // BlockSize returns the size of each block supported by this cipher stream.
  virtual size_t BlockSize() {return AES_BLOCK_SIZE;};

  // Encrypt one or more (partial) blocks of data at the file offset.
  // Length of data is given in dataSize.
  virtual Status Encrypt(uint64_t fileOffset, char *data, size_t dataSize);

  // Decrypt one or more (partial) blocks of data at the file offset.
  // Length of data is given in dataSize.
  virtual Status Decrypt(uint64_t fileOffset, char *data, size_t dataSize);

protected:
  // Allocate scratch space which is passed to EncryptBlock/DecryptBlock.
  virtual void AllocateScratch(std::string&) {};

  // Encrypt a block of data at the given block index.
  // Length of data is equal to BlockSize();
  virtual Status EncryptBlock(uint64_t blockIndex, char *data, char* scratch);// {return Status::OK();}

  // Decrypt a block of data at the given block index.
  // Length of data is equal to BlockSize();
  virtual Status DecryptBlock(uint64_t blockIndex, char *data, char* scratch);// {return Status::OK();}

  const AES_KEY & key_;  // should we have a copy of this?
      uint8_t code_version_;
      uint8_t nonce_[AES_BLOCK_SIZE/2];

};



class CTREncryptionProvider2 : public CTREncryptionProvider {
public:

  virtual size_t GetPrefixLength() override {return sizeof(Prefix0_t) + sizeof(EncryptMarker_t);}

  virtual Status CreateNewPrefix(const std::string& /*fname*/, char *prefix, size_t prefixLength) override
  {
    Status s;
    if (sizeof(Prefix0_t)<=prefixLength) {
      int ret_val;

      Prefix0_t * pf={(Prefix0_t *)prefix};
      memcpy((void *)pf->key_description_,(void *)key_desc_, sizeof(Sha1Description_t));
      ret_val = RAND_bytes((unsigned char *)&pf->nonce_, AES_BLOCK_SIZE/2);  //RAND_poll() to initialize
      if (1 != ret_val) {
        s = Status::NotSupported("RAND_bytes failed");
      }
    } else {
      s = Status::NotSupported("Prefix size needs to be 28 or more");
    }

    return s;
  }

  virtual Status CreateCipherStream(
    const std::string& /*fname*/, const EnvOptions& /*options*/, Slice& /*prefix*/,
    std::unique_ptr<BlockAccessCipherStream>* /*result*/) override
  {return Status::NotSupported("Wrong EncryptionProvider assumed");}

  virtual BlockAccessCipherStream * CreateCipherStream2(
    uint8_t code_version, uint8_t nonce[]) {
    return new AESBlockAccessCipherStream(key_, code_version, nonce);
  }

  const AES_KEY & key() const {return key_;};

protected:
  Sha1Description_t key_desc_;
  AES_KEY key_;

};


// EncryptedEnv2 implements an Env wrapper that adds encryption to files stored on disk.

class EncryptedEnv2 : public EnvWrapper {
 public:
  EncryptedEnv2(Env* base_env, std::map<Sha1Description_t,
                std::shared_ptr<EncryptionProvider>> && encrypt_read,
                std::pair<Sha1Description_t,std::shared_ptr<EncryptionProvider>> && encrypt_write)
    : EnvWrapper(base_env), encrypt_read_(encrypt_read), encrypt_write_(encrypt_write) {
    RAND_poll();
  }

  bool IsWriteEncrypted() const {return nullptr!=encrypt_write_.second;}

  // NewSequentialFile opens a file for sequential reading.
  virtual Status NewSequentialFile(const std::string& fname,
                                   std::unique_ptr<SequentialFile>* result,
                                   const EnvOptions& options) override {
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
  virtual Status NewRandomAccessFile(const std::string& fname,
                                     std::unique_ptr<RandomAccessFile>* result,
                                     const EnvOptions& options) override {
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
  virtual Status NewWritableFile(const std::string& fname,
                                 std::unique_ptr<WritableFile>* result,
                                 const EnvOptions& options) override {
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
  virtual Status ReopenWritableFile(const std::string& fname,
                                    std::unique_ptr<WritableFile>* result,
                                    const EnvOptions& options) override {
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
  virtual Status ReuseWritableFile(const std::string& fname,
                                   const std::string& old_fname,
                                   std::unique_ptr<WritableFile>* result,
                                   const EnvOptions& options) override {
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
  virtual Status NewRandomRWFile(const std::string& fname,
                                 std::unique_ptr<RandomRWFile>* result,
                                 const EnvOptions& options) override {
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
  virtual Status GetChildrenFileAttributes(const std::string& dir, std::vector<FileAttributes>* result) override {
    auto status = EnvWrapper::GetChildrenFileAttributes(dir, result);
#if 0
// do we really need to adjust all of these file sizes if encrypted?
    if (!status.ok()) {
      return status;
    }
    size_t prefixLength = provider_->GetPrefixLength();
    for (auto it = std::begin(*result); it!=std::end(*result); ++it) {
      assert(it->size_bytes >= prefixLength);
      it->size_bytes -= prefixLength;
    }
#endif
    return status;
 }

  // Store the size of fname in *file_size.
  virtual Status GetFileSize(const std::string& fname, uint64_t* file_size) override {
    Status status;
    status = EnvWrapper::GetFileSize(fname, file_size);
#if 0
// do we really need to adjust all of these file sizes if encrypted?
    if (status.ok()) {
      std::shared_ptr<EncryptionProvider> provider;
      status = GetEncryptionProvider(fname, provider);
      if (status.ok() && provider) {
        size_t prefixLength = provider->GetPrefixLength();
        assert(*file_size >= prefixLength);
        *file_size -= prefixLength;
      }
    }
#endif
    return status;
  }

#if 0
// only needed for GetChildrenFileAttributes & GetFileSize
  virtual Status GetEncryptionProvider(const std::string& fname, std::shared_ptr<EncryptionProvider> & provider) {
    std::unique_ptr<SequentialFile> underlying;
    EnvOptions options;
    Status status;
    EncryptMarker_t marker;
    Slice marker_slice;

    provider.reset();
    status = EnvWrapper::NewSequentialFile(fname, &underlying, options);
    if (status.ok()) {
      // Look for encryption marker
      status = underlying->Read(sizeof(marker), &marker_slice, marker);
    }

    if (status.ok()) {
      if (marker_slice.starts_with(Marker)) {
        uint8_t code_version = (uint8_t)marker_slice[7];
        std::unique_ptr<BlockAccessCipherStream> stream;

        status=ReadSeqEncryptionPrefix(&underlying, provider, stream);
      } else {
        // normal file, not encrypted
      }
    }

    return status;
  }
#endif


  template <class TypeFile> Status ReadSeqEncryptionPrefix(TypeFile * f,
                                      std::shared_ptr<EncryptionProvider> & provider,
                                      std::unique_ptr<BlockAccessCipherStream> & stream) {
    Status status;

    provider.reset(); // nullptr for provider implies "no encryption"
    stream.release();

    // Look for encryption marker
    EncryptMarker_t marker;
    Slice marker_slice;
    status = f->Read(sizeof(marker)+1, &marker_slice, marker);
    if (status.ok()) {
      if (sizeof(marker)<marker_slice.size() && marker_slice.starts_with(Marker)) {

        // code_version currently unused
        uint8_t code_version = (uint8_t)marker_slice[7];

        Slice prefix_slice;
        Prefix0_t prefix_buffer;
        status = f->Read(sizeof(Prefix0_t), &prefix_slice, (char *)&prefix_buffer);
        if (status.ok() && sizeof(Prefix0_t) == prefix_slice.size()) {

          auto it = encrypt_read_.find(prefix_buffer.key_description_);
          if (encrypt_read_.end() != it) {
            CTREncryptionProvider2 * ptr=(CTREncryptionProvider2 *)it->second.get();
            provider=it->second;
            stream.reset(new AESBlockAccessCipherStream(ptr->key(), code_version, prefix_buffer.nonce_));;
          } else {
            status = Status::NotSupported("No encryption key found to match input file");
          }
        }
      }
    }
    return status;
  }

  template <class TypeFile> Status ReadRandEncryptionPrefix(TypeFile * f,
                                      std::shared_ptr<EncryptionProvider> & provider,
                                      std::unique_ptr<BlockAccessCipherStream> & stream) {
    Status status;

    provider.reset(); // nullptr for provider implies "no encryption"
    stream.release();

    // Look for encryption marker
    EncryptMarker_t marker;
    Slice marker_slice;
    status = f->Read(0, sizeof(marker)+1, &marker_slice, marker);
    if (status.ok()) {
      if (sizeof(marker)<marker_slice.size() && marker_slice.starts_with(Marker)) {

        // code_version currently unused
        uint8_t code_version = (uint8_t)marker_slice[7];

        Slice prefix_slice;
        Prefix0_t prefix_buffer;
        status = f->Read(sizeof(marker)+1, sizeof(Prefix0_t), &prefix_slice, (char *)&prefix_buffer);
        if (status.ok() && sizeof(Prefix0_t) == prefix_slice.size()) {

          auto it = encrypt_read_.find(prefix_buffer.key_description_);
          if (encrypt_read_.end() != it) {
            CTREncryptionProvider2 * ptr=(CTREncryptionProvider2 *)it->second.get();
            provider=it->second;
            stream.reset(new AESBlockAccessCipherStream(ptr->key(), code_version, prefix_buffer.nonce_));
          } else {
            status = Status::NotSupported("No encryption key found to match input file");
          }
        }
      }
    }
    return status;
  }


  template <class TypeFile> Status WriteSeqEncryptionPrefix(TypeFile * f,
                                      std::unique_ptr<BlockAccessCipherStream> & stream) {
    Status status;

    // set up Encryption maker, code version '0'
    uint8_t code_version={'0'};
    Prefix0_t prefix;
    EncryptMarker_t marker;
    strncpy(marker, Marker, sizeof(Marker));
    marker[sizeof(EncryptMarker_t)-1]=code_version;

    Slice marker_slice(marker, sizeof(EncryptMarker_t));
    status = f->Append(marker_slice);

    if (status.ok()) {
      // create nonce, then write it and key description
      Slice prefix_slice((char *)&prefix, sizeof(prefix));

      status = encrypt_write_.second->CreateNewPrefix(std::string(), (char *)&prefix, encrypt_write_.second->GetPrefixLength());

      if (status.ok()) {
        status = f->Append(prefix_slice);
      }
    }

    if (status.ok()) {
      CTREncryptionProvider2 * ptr=(CTREncryptionProvider2 *)encrypt_write_.second.get();
      stream.reset(new AESBlockAccessCipherStream(ptr->key(), code_version, prefix.nonce_));
    }

    return status;
  }


  template <class TypeFile> Status WriteRandEncryptionPrefix(TypeFile * f,
                                      std::unique_ptr<BlockAccessCipherStream> & stream) {
    Status status;

    // set up Encryption maker, code version '0'
    uint8_t code_version={'0'};
    Prefix0_t prefix;
    EncryptMarker_t marker;
    strncpy(marker, Marker, sizeof(Marker));
    marker[sizeof(EncryptMarker_t)-1]=code_version;

    Slice marker_slice(marker, sizeof(EncryptMarker_t));
    status = f->Write(0, marker_slice);

    if (status.ok()) {
      // create nonce, then write it and key description
      Slice prefix_slice((char *)&prefix, sizeof(prefix));

      status = encrypt_write_.second->CreateNewPrefix(std::string(), (char *)&prefix, encrypt_write_.second->GetPrefixLength());

      if (status.ok()) {
        status = f->Write(sizeof(EncryptMarker_t), prefix_slice);
      }
    }

    if (status.ok()) {
      CTREncryptionProvider2 * ptr=(CTREncryptionProvider2 *)encrypt_write_.second.get();
      stream.reset(new AESBlockAccessCipherStream(ptr->key(), code_version, prefix.nonce_));
    }

    return status;
  }


protected:

  std::map<Sha1Description_t,std::shared_ptr<EncryptionProvider>> encrypt_read_;
  std::pair<Sha1Description_t,std::shared_ptr<EncryptionProvider>> encrypt_write_;
};



// Returns an Env that encrypts data when stored on disk and decrypts data when
// read from disk.
Env* NewEncryptedEnv2(Env* base_env,
                      std::map<Sha1Description_t,std::shared_ptr<EncryptionProvider>> & encrypt_read,
                      std::pair<Sha1Description_t,std::shared_ptr<EncryptionProvider>> & encrypt_write) {
  return new EncryptedEnv2(base_env, encrypt_read, encrypt_write);
}

#if 0
// Encrypt one or more (partial) blocks of data at the file offset.
// Length of data is given in dataSize.
Status BlockAccessCipherStream::Encrypt(uint64_t fileOffset, char *data, size_t dataSize) {
  // Calculate block index
  auto blockSize = BlockSize();
  uint64_t blockIndex = fileOffset / blockSize;
  size_t blockOffset = fileOffset % blockSize;
  std::unique_ptr<char[]> blockBuffer;

  std::string scratch;
  AllocateScratch(scratch);

  // Encrypt individual blocks.
  while (1) {
    char *block = data;
    size_t n = std::min(dataSize, blockSize - blockOffset);
    if (n != blockSize) {
      // We're not encrypting a full block.
      // Copy data to blockBuffer
      if (!blockBuffer.get()) {
        // Allocate buffer
        blockBuffer = std::unique_ptr<char[]>(new char[blockSize]);
      }
      block = blockBuffer.get();
      // Copy plain data to block buffer
      memmove(block + blockOffset, data, n);
    }
    auto status = EncryptBlock(blockIndex, block, (char*)scratch.data());
    if (!status.ok()) {
      return status;
    }
    if (block != data) {
      // Copy encrypted data back to `data`.
      memmove(data, block + blockOffset, n);
    }
    dataSize -= n;
    if (dataSize == 0) {
      return Status::OK();
    }
    data += n;
    blockOffset = 0;
    blockIndex++;
  }
}

// Decrypt one or more (partial) blocks of data at the file offset.
// Length of data is given in dataSize.
Status BlockAccessCipherStream::Decrypt(uint64_t fileOffset, char *data, size_t dataSize) {
  // Calculate block index
  auto blockSize = BlockSize();
  uint64_t blockIndex = fileOffset / blockSize;
  size_t blockOffset = fileOffset % blockSize;
  std::unique_ptr<char[]> blockBuffer;

  std::string scratch;
  AllocateScratch(scratch);

  // Decrypt individual blocks.
  while (1) {
    char *block = data;
    size_t n = std::min(dataSize, blockSize - blockOffset);
    if (n != blockSize) {
      // We're not decrypting a full block.
      // Copy data to blockBuffer
      if (!blockBuffer.get()) {
        // Allocate buffer
        blockBuffer = std::unique_ptr<char[]>(new char[blockSize]);
      }
      block = blockBuffer.get();
      // Copy encrypted data to block buffer
      memmove(block + blockOffset, data, n);
    }
    auto status = DecryptBlock(blockIndex, block, (char*)scratch.data());
    if (!status.ok()) {
      return status;
    }
    if (block != data) {
      // Copy decrypted data back to `data`.
      memmove(data, block + blockOffset, n);
    }
    dataSize -= n;
    if (dataSize == 0) {
      return Status::OK();
    }
    data += n;
    blockOffset = 0;
    blockIndex++;
  }
}

// Encrypt a block of data.
// Length of data is equal to BlockSize().
Status ROT13BlockCipher::Encrypt(char *data) {
  for (size_t i = 0; i < blockSize_; ++i) {
      data[i] += 13;
  }
  return Status::OK();
}

// Decrypt a block of data.
// Length of data is equal to BlockSize().
Status ROT13BlockCipher::Decrypt(char *data) {
  return Encrypt(data);
}

// Allocate scratch space which is passed to EncryptBlock/DecryptBlock.
void CTRCipherStream::AllocateScratch(std::string& scratch) {
  auto blockSize = cipher_.BlockSize();
  scratch.reserve(blockSize);
}

// Encrypt a block of data at the given block index.
// Length of data is equal to BlockSize();
Status CTRCipherStream::EncryptBlock(uint64_t blockIndex, char *data, char* scratch) {

  // Create nonce + counter
  auto blockSize = cipher_.BlockSize();
  memmove(scratch, iv_.data(), blockSize);
  EncodeFixed64(scratch, blockIndex + initialCounter_);

  // Encrypt nonce+counter
  auto status = cipher_.Encrypt(scratch);
  if (!status.ok()) {
    return status;
  }

  // XOR data with ciphertext.
  for (size_t i = 0; i < blockSize; i++) {
    data[i] = data[i] ^ scratch[i];
  }
  return Status::OK();
}

// Decrypt a block of data at the given block index.
// Length of data is equal to BlockSize();
Status CTRCipherStream::DecryptBlock(uint64_t blockIndex, char *data, char* scratch) {
  // For CTR decryption & encryption are the same
  return EncryptBlock(blockIndex, data, scratch);
}

// GetPrefixLength returns the length of the prefix that is added to every file
// and used for storing encryption options.
// For optimal performance, the prefix length should be a multiple of
// the page size.
size_t CTREncryptionProvider::GetPrefixLength() {
  return defaultPrefixLength;
}

// decodeCTRParameters decodes the initial counter & IV from the given
// (plain text) prefix.
static void decodeCTRParameters(const char *prefix, size_t blockSize, uint64_t &initialCounter, Slice &iv) {
  // First block contains 64-bit initial counter
  initialCounter = DecodeFixed64(prefix);
  // Second block contains IV
  iv = Slice(prefix + blockSize, blockSize);
}

// CreateNewPrefix initialized an allocated block of prefix memory
// for a new file.
Status CTREncryptionProvider::CreateNewPrefix(const std::string& /*fname*/,
                                              char* prefix,
                                              size_t prefixLength) {
  // Create & seed rnd.
  Random rnd((uint32_t)Env::Default()->NowMicros());
  // Fill entire prefix block with random values.
  for (size_t i = 0; i < prefixLength; i++) {
    prefix[i] = rnd.Uniform(256) & 0xFF;
  }
  // Take random data to extract initial counter & IV
  auto blockSize = cipher_.BlockSize();
  uint64_t initialCounter;
  Slice prefixIV;
  decodeCTRParameters(prefix, blockSize, initialCounter, prefixIV);

  // Now populate the rest of the prefix, starting from the third block.
  PopulateSecretPrefixPart(prefix + (2 * blockSize), prefixLength - (2 * blockSize), blockSize);

  // Encrypt the prefix, starting from block 2 (leave block 0, 1 with initial counter & IV unencrypted)
  CTRCipherStream cipherStream(cipher_, prefixIV.data(), initialCounter);
  auto status = cipherStream.Encrypt(0, prefix + (2 * blockSize), prefixLength - (2 * blockSize));
  if (!status.ok()) {
    return status;
  }
  return Status::OK();
}

// PopulateSecretPrefixPart initializes the data into a new prefix block
// in plain text.
// Returns the amount of space (starting from the start of the prefix)
// that has been initialized.
size_t CTREncryptionProvider::PopulateSecretPrefixPart(char* /*prefix*/,
                                                       size_t /*prefixLength*/,
                                                       size_t /*blockSize*/) {
  // Nothing to do here, put in custom data in override when needed.
  return 0;
}

Status CTREncryptionProvider::CreateCipherStream(
    const std::string& fname, const EnvOptions& options, Slice& prefix,
    std::unique_ptr<BlockAccessCipherStream>* result) {
  // Read plain text part of prefix.
  auto blockSize = cipher_.BlockSize();
  uint64_t initialCounter;
  Slice iv;
  decodeCTRParameters(prefix.data(), blockSize, initialCounter, iv);

  // Decrypt the encrypted part of the prefix, starting from block 2 (block 0, 1 with initial counter & IV are unencrypted)
  CTRCipherStream cipherStream(cipher_, iv.data(), initialCounter);
  auto status = cipherStream.Decrypt(0, (char*)prefix.data() + (2 * blockSize), prefix.size() - (2 * blockSize));
  if (!status.ok()) {
    return status;
  }

  // Create cipher stream
  return CreateCipherStreamFromPrefix(fname, options, initialCounter, iv, prefix, result);
}

// CreateCipherStreamFromPrefix creates a block access cipher stream for a file given
// given name and options. The given prefix is already decrypted.
Status CTREncryptionProvider::CreateCipherStreamFromPrefix(
    const std::string& /*fname*/, const EnvOptions& /*options*/,
    uint64_t initialCounter, const Slice& iv, const Slice& /*prefix*/,
    std::unique_ptr<BlockAccessCipherStream>* result) {
  (*result) = std::unique_ptr<BlockAccessCipherStream>(
      new CTRCipherStream(cipher_, iv.data(), initialCounter));
  return Status::OK();
}
#endif // 0
#endif // ROCKSDB_LITE

}  // namespace rocksdb
