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

#include "openssl/aes.h"
#include "openssl/evp.h"
#include "openssl/rand.h"

#include "rocksdb/env_encryption.h"
#include "util/aligned_buffer.h"
#include "util/coding.h"
#include "util/random.h"

#endif

namespace rocksdb {

#ifndef ROCKSDB_LITE

struct Sha1Description_t {
  uint8_t desc[EVP_MAX_MD_SIZE];
  bool valid;

  Sha1Description_t() : valid(false) {
    memset(desc, 0, EVP_MAX_MD_SIZE);
  }

  Sha1Description_t(uint8_t * Desc, size_t DescLen) : valid(false) {
    memset(desc, 0, EVP_MAX_MD_SIZE);
    if (DescLen<=EVP_MAX_MD_SIZE) {
      memcpy(desc, Desc, DescLen);
      valid = true;
    }
  }

  Sha1Description_t(const std::string KeyDescStr) {
    bool good={true};
    int ret_val;
    unsigned len;

    memset(desc, 0, EVP_MAX_MD_SIZE);
    if (0 != KeyDescStr.length()) {
      std::unique_ptr<EVP_MD_CTX, void(*)(EVP_MD_CTX *)> context(EVP_MD_CTX_new(), EVP_MD_CTX_free);

      ret_val = EVP_DigestInit_ex(context.get(), EVP_sha1(), nullptr);
      good = (1 == ret_val);
      if (good) {
        ret_val = EVP_DigestUpdate(context.get(), KeyDescStr.c_str(), KeyDescStr.length());
        good = (1 == ret_val);
      }

      if (good) {
        ret_val = EVP_DigestFinal_ex(context.get(), desc, &len);
        good = (1 == ret_val);
      }
    } else {
      good = false;
    }

    valid = good;
  }

  // goal is to explicitly remove desc from memory once no longer needed
  ~Sha1Description_t() {
    memset(desc, 0, EVP_MAX_MD_SIZE);
    valid = false;
  }

  bool operator<(const Sha1Description_t &rhs) const {
    return memcmp(desc, rhs.desc, EVP_MAX_MD_SIZE)<0;
  }
};

struct AesCtrKey_t {
  uint8_t key[EVP_MAX_KEY_LENGTH];
  bool valid;

  AesCtrKey_t() : valid(false) {
    memset(key, 0, EVP_MAX_KEY_LENGTH);
  }

  AesCtrKey_t(const uint8_t * Key, size_t KeyLen) {
    memset(key, 0, EVP_MAX_KEY_LENGTH);
    if (KeyLen <= EVP_MAX_KEY_LENGTH) {
      memcpy(key, Key, KeyLen);
      valid = true;
    } else {
      valid = false;
    }
  }

  // goal is to explicitly remove key from memory once no longer needed
  ~AesCtrKey_t() {
    memset(key, 0, EVP_MAX_KEY_LENGTH);
    valid = false;
  }

};

typedef char EncryptMarker_t[8];
static EncryptMarker_t Marker = "Encrypt";

// long term:  code_version could be used in a switch statement or factory parameter
// version 0 is 12 byte sha1 description hash, 128 bit (16 byte) nounce (assumed to be packed/byte aligned)
typedef struct {
  uint8_t key_description_[EVP_MAX_MD_SIZE];
  uint8_t nonce_[AES_BLOCK_SIZE/2];      // block size is 16
} Prefix0_t;


class AESBlockAccessCipherStream : public BlockAccessCipherStream {
public:
  AESBlockAccessCipherStream(const AesCtrKey_t & key, uint8_t code_version, uint8_t nonce[])
    : key_(key), code_version_(code_version) {
    memcpy(&nonce_, nonce, AES_BLOCK_SIZE/2);
  }

  // BlockSize returns the size of each block supported by this cipher stream.
  virtual size_t BlockSize() {return AES_BLOCK_SIZE;};

  // Encrypt one or more (partial) blocks of data at the file offset.
  // Length of data is given in dataSize.
//  virtual Status Encrypt(uint64_t /*fileOffset*/, char */*data*/, size_t /*dataSize*/) {return Status::OK();}

  // Decrypt one or more (partial) blocks of data at the file offset.
  // Length of data is given in dataSize.
//  virtual Status Decrypt(uint64_t /*fileOffset*/, char */*data*/, size_t /*dataSize*/) {return Status::OK();}

protected:
  // Allocate scratch space which is passed to EncryptBlock/DecryptBlock.
  virtual void AllocateScratch(std::string&) {};

  // Encrypt a block of data at the given block index.
  // Length of data is equal to BlockSize();
  virtual Status EncryptBlock(uint64_t blockIndex, char *data, char* scratch) override;

  // Decrypt a block of data at the given block index.
  // Length of data is equal to BlockSize();
  virtual Status DecryptBlock(uint64_t blockIndex, char *data, char* scratch) override;

  AesCtrKey_t key_;
  uint8_t code_version_;
  uint8_t nonce_[AES_BLOCK_SIZE/2];

};



class CTREncryptionProvider2 : public EncryptionProvider {
public:
  CTREncryptionProvider2() = delete;

  CTREncryptionProvider2(const Sha1Description_t & key_desc, const AesCtrKey_t & key)
    : valid_(true), key_desc_(key_desc), key_(key) {}

  CTREncryptionProvider2(const std::string & key_desc_str,
                         const uint8_t unformatted_key[], int bytes)
    : valid_(false), key_desc_(key_desc_str), key_(unformatted_key, bytes) {}

  virtual size_t GetPrefixLength() override {return sizeof(Prefix0_t) + sizeof(EncryptMarker_t);}

  virtual Status CreateNewPrefix(const std::string& /*fname*/, char *prefix, size_t prefixLength) override
  {
    Status s;
    if (sizeof(Prefix0_t)<=prefixLength) {
      int ret_val;

      Prefix0_t * pf={(Prefix0_t *)prefix};
      memcpy(pf->key_description_,key_desc_.desc, sizeof(key_desc_.desc));
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

  bool Valid() const {return valid_;};
  const Sha1Description_t & key_desc() const {return key_desc_;};
  const AesCtrKey_t & key() const {return key_;};

protected:
  bool valid_;
  Sha1Description_t key_desc_;
  AesCtrKey_t key_;

};


// EncryptedEnv2 implements an Env wrapper that adds encryption to files stored on disk.

class EncryptedEnv2 : public EnvWrapper {
 public:
  EncryptedEnv2(Env* base_env,
                std::map<Sha1Description_t, std::shared_ptr<EncryptionProvider>> encrypt_read,
                std::pair<Sha1Description_t,std::shared_ptr<EncryptionProvider>> encrypt_write)
    : EnvWrapper(base_env), encrypt_read_(encrypt_read), encrypt_write_(encrypt_write) {
    RAND_poll();
  }

  bool IsWriteEncrypted() const {return nullptr!=encrypt_write_.second;}

  // NewSequentialFile opens a file for sequential reading.
  virtual Status NewSequentialFile(const std::string& fname,
                                   std::unique_ptr<SequentialFile>* result,
                                   const EnvOptions& options) override;

  // NewRandomAccessFile opens a file for random read access.
  virtual Status NewRandomAccessFile(const std::string& fname,
                                     std::unique_ptr<RandomAccessFile>* result,
                                     const EnvOptions& options) override;

  // NewWritableFile opens a file for sequential writing.
  virtual Status NewWritableFile(const std::string& fname,
                                 std::unique_ptr<WritableFile>* result,
                                 const EnvOptions& options) override;

  // Create an object that writes to a new file with the specified
  // name.  Deletes any existing file with the same name and creates a
  // new file.  On success, stores a pointer to the new file in
  // *result and returns OK.  On failure stores nullptr in *result and
  // returns non-OK.
  //
  // The returned file will only be accessed by one thread at a time.
  virtual Status ReopenWritableFile(const std::string& fname,
                                    std::unique_ptr<WritableFile>* result,
                                    const EnvOptions& options) override;

  // Reuse an existing file by renaming it and opening it as writable.
  virtual Status ReuseWritableFile(const std::string& fname,
                                   const std::string& old_fname,
                                   std::unique_ptr<WritableFile>* result,
                                   const EnvOptions& options) override;

  // Open `fname` for random read and write, if file doesn't exist the file
  // will be created.  On success, stores a pointer to the new file in
  // *result and returns OK.  On failure returns non-OK.
  //
  // The returned file will only be accessed by one thread at a time.
  virtual Status NewRandomRWFile(const std::string& fname,
                                 std::unique_ptr<RandomRWFile>* result,
                                 const EnvOptions& options) override;

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
  virtual Status GetChildrenFileAttributes(const std::string& dir, std::vector<FileAttributes>* result) override;

  // Store the size of fname in *file_size.
  virtual Status GetFileSize(const std::string& fname, uint64_t* file_size) override;

  // only needed for GetChildrenFileAttributes & GetFileSize
  virtual Status GetEncryptionProvider(const std::string& fname, std::shared_ptr<EncryptionProvider> & provider);


  template <class TypeFile> Status ReadSeqEncryptionPrefix(TypeFile * f,
                                      std::shared_ptr<EncryptionProvider> & provider,
                                      std::unique_ptr<BlockAccessCipherStream> & stream) {
    Status status;

    provider.reset(); // nullptr for provider implies "no encryption"
    stream.release();

    // Look for encryption marker
    EncryptMarker_t marker;
    Slice marker_slice;
    status = f->Read(sizeof(marker), &marker_slice, marker);
    if (status.ok()) {
      if (sizeof(marker) == marker_slice.size() && marker_slice.starts_with(Marker)) {

        // code_version currently unused
        uint8_t code_version = (uint8_t)marker_slice[7];

        Slice prefix_slice;
        Prefix0_t prefix_buffer;
        status = f->Read(sizeof(Prefix0_t), &prefix_slice, (char *)&prefix_buffer);
        if (status.ok() && sizeof(Prefix0_t) == prefix_slice.size()) {
          Sha1Description_t desc(prefix_buffer.key_description_, sizeof(prefix_buffer.key_description_));

          auto it = encrypt_read_.find(desc);
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
    status = f->Read(0, sizeof(marker), &marker_slice, marker);
    if (status.ok()) {
      if (sizeof(marker) == marker_slice.size() && marker_slice.starts_with(Marker)) {

        // code_version currently unused
        uint8_t code_version = (uint8_t)marker_slice[7];

        Slice prefix_slice;
        Prefix0_t prefix_buffer;
        status = f->Read(sizeof(marker), sizeof(Prefix0_t), &prefix_slice, (char *)&prefix_buffer);
        if (status.ok() && sizeof(Prefix0_t) == prefix_slice.size()) {
          Sha1Description_t desc(prefix_buffer.key_description_, sizeof(prefix_buffer.key_description_));

          auto it = encrypt_read_.find(desc);
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
                      std::map<Sha1Description_t,std::shared_ptr<EncryptionProvider>> encrypt_read,
                      std::pair<Sha1Description_t,std::shared_ptr<EncryptionProvider>> encrypt_write);


#endif // ROCKSDB_LITE

}  // namespace rocksdb
