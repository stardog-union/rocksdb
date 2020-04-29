// Copyright (c) 2011 The LevelDB Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file. See the AUTHORS file for names of contributors.


#include "rocksdb/env_encrypt_2.h"

#include "util/testharness.h"

namespace rocksdb {

class EnvEncrypt2_Sha1 {};

TEST(EnvEncrypt2_Sha1, Default) {
  Sha1Description_t desc;

  ASSERT_FALSE(desc.IsValid());
  for (size_t idx=0; idx<sizeof(desc.desc); ++idx) {
    ASSERT_TRUE('\0' == desc.desc[idx]);
  }
}

TEST(EnvEncrypt2_Sha1, Constructors) {
  Sha1Description_t desc;

  // verify we know size of desc.desc
  ASSERT_TRUE(64 == sizeof(desc.desc));

  uint8_t bytes[128], *ptr;
  for (size_t idx=0; idx<sizeof(bytes); ++idx) {
    bytes[idx] = idx+1;
  }

  Sha1Description_t desc_bad1(bytes, 128);
  ASSERT_FALSE(desc_bad1.IsValid());

  Sha1Description_t desc_bad2(bytes, 65);
  ASSERT_FALSE(desc_bad2.IsValid());

  Sha1Description_t desc_good1(bytes, 64);
  ASSERT_TRUE(desc_good1.IsValid());
  ptr = (uint8_t *)memchr(desc_good1.desc, 0, 64);
  ASSERT_TRUE(nullptr == ptr);

  Sha1Description_t desc_good2(bytes, 63);
  ASSERT_TRUE(desc_good2.IsValid());
  ptr = (uint8_t *)memchr(desc_good2.desc, 0, 64);
  ASSERT_TRUE(&desc_good2.desc[63] == ptr);

  Sha1Description_t desc_good3(bytes, 1);
  ASSERT_TRUE(desc_good3.IsValid());
  ptr = (uint8_t *)memchr(desc_good3.desc, 0, 64);
  ASSERT_TRUE(&desc_good3.desc[1] == ptr);

  Sha1Description_t desc_good4(bytes, 0);
  ASSERT_TRUE(desc_good4.IsValid());
  ptr = (uint8_t *)memchr(desc_good4.desc, 0, 64);
  ASSERT_TRUE(&desc_good4.desc[0] == ptr);

  Sha1Description_t desc_str1("");
  ASSERT_FALSE(desc_str1.IsValid());

  uint8_t md2[] = {0x35, 0x6a, 0x19, 0x2b, 0x79, 0x13, 0xb0, 0x4c,
                   0x54, 0x57, 0x4d, 0x18, 0xc2, 0x8d, 0x46, 0xe6,
                   0x39, 0x54, 0x28, 0xab};
  Sha1Description_t desc_str2("1");
  ASSERT_TRUE(desc_str2.IsValid());
  ASSERT_TRUE(0 == memcmp(md2, desc_str2.desc, sizeof(md2)));
  for (size_t idx=sizeof(md2); idx<sizeof(desc_str2.desc); ++idx) {
    ASSERT_TRUE( 0 == desc_str2.desc[idx]);
  }

  uint8_t md3[] = {0x7b, 0x52, 0x00, 0x9b, 0x64, 0xfd, 0x0a, 0x2a,
                   0x49, 0xe6, 0xd8, 0xa9, 0x39, 0x75, 0x30, 0x77,
                   0x79, 0x2b, 0x05, 0x54};
  Sha1Description_t desc_str3("12");
  ASSERT_TRUE(desc_str3.IsValid());
  ASSERT_TRUE(0 == memcmp(md3, desc_str3.desc, sizeof(md3)));
  for (size_t idx=sizeof(md3); idx<sizeof(desc_str3.desc); ++idx) {
    ASSERT_TRUE( 0 == desc_str3.desc[idx]);
  }
}

TEST(EnvEncrypt2_Sha1, Copy) {
  // assignment
  uint8_t md1[] = {0xdb, 0x8a, 0xc1, 0xc2, 0x59, 0xeb, 0x89, 0xd4,
                   0xa1, 0x31, 0xb2, 0x53, 0xba, 0xcf, 0xca, 0x5f,
                   0x31, 0x9d, 0x54, 0xf2};
  Sha1Description_t desc1("HelloWorld"), desc2;
  ASSERT_TRUE(desc1.IsValid());
  ASSERT_FALSE(desc2.IsValid());

  desc2 = desc1;
  ASSERT_TRUE(desc1.IsValid());
  ASSERT_TRUE(desc2.IsValid());
  ASSERT_TRUE(0 == memcmp(md1, desc1.desc, sizeof(md1)));
  for (size_t idx=sizeof(md1); idx<sizeof(desc1.desc); ++idx) {
    ASSERT_TRUE( 0 == desc1.desc[idx]);
  }
  ASSERT_TRUE(0 == memcmp(md1, desc2.desc, sizeof(md1)));
  for (size_t idx=sizeof(md1); idx<sizeof(desc2.desc); ++idx) {
    ASSERT_TRUE( 0 == desc2.desc[idx]);
  }

  // copy constructor
  uint8_t md3[] = {0x17, 0x09, 0xcc, 0x51, 0x65, 0xf5, 0x50, 0x4d,
                   0x46, 0xde, 0x2f, 0x3a, 0x7a, 0xff, 0x57, 0x45,
                   0x20, 0x8a, 0xed, 0x44};
  Sha1Description_t desc3("A little be longer title for a key");
  ASSERT_TRUE(desc3.IsValid());

  Sha1Description_t desc4(desc3);
  ASSERT_TRUE(desc3.IsValid());
  ASSERT_TRUE(desc4.IsValid());
  ASSERT_TRUE(0 == memcmp(md3, desc3.desc, sizeof(md3)));
  for (size_t idx=sizeof(md3); idx<sizeof(desc3.desc); ++idx) {
    ASSERT_TRUE( 0 == desc3.desc[idx]);
  }
  ASSERT_TRUE(0 == memcmp(md3, desc4.desc, sizeof(md3)));
  for (size_t idx=sizeof(md3); idx<sizeof(desc4.desc); ++idx) {
    ASSERT_TRUE( 0 == desc4.desc[idx]);
  }
}

class EnvEncrypt2_Key {};

TEST(EnvEncrypt2_Key, Default) {
  AesCtrKey_t key;

  ASSERT_FALSE(key.IsValid());
  for (size_t idx=0; idx<sizeof(key.key); ++idx) {
    ASSERT_TRUE('\0' == key.key[idx]);
  }
}

TEST(EnvEncrypt2_Key, Constructors) {
  AesCtrKey_t key;

  // verify we know size of key.key
  ASSERT_TRUE(64 == sizeof(key.key));

  uint8_t bytes[128], *ptr;
  for (size_t idx=0; idx<sizeof(bytes); ++idx) {
    bytes[idx] = idx+1;
  }

  AesCtrKey_t key_bad1(bytes, 128);
  ASSERT_FALSE(key_bad1.IsValid());

  AesCtrKey_t key_bad2(bytes, 65);
  ASSERT_FALSE(key_bad2.IsValid());

  AesCtrKey_t key_good1(bytes, 64);
  ASSERT_TRUE(key_good1.IsValid());
  ptr = (uint8_t *)memchr(key_good1.key, 0, 64);
  ASSERT_TRUE(nullptr == ptr);

  AesCtrKey_t key_good2(bytes, 63);
  ASSERT_TRUE(key_good2.IsValid());
  ptr = (uint8_t *)memchr(key_good2.key, 0, 64);
  ASSERT_TRUE(&key_good2.key[63] == ptr);

  AesCtrKey_t key_good3(bytes, 1);
  ASSERT_TRUE(key_good3.IsValid());
  ptr = (uint8_t *)memchr(key_good3.key, 0, 64);
  ASSERT_TRUE(&key_good3.key[1] == ptr);

  AesCtrKey_t key_good4(bytes, 0);
  ASSERT_TRUE(key_good4.IsValid());
  ptr = (uint8_t *)memchr(key_good4.key, 0, 64);
  ASSERT_TRUE(&key_good4.key[0] == ptr);

  AesCtrKey_t key_str1("");
  ASSERT_FALSE(key_str1.IsValid());

  AesCtrKey_t key_str2("0x35");
  ASSERT_FALSE(key_str2.IsValid());

                      //1234567890123456789012345678901234567890123456789012345678901234
  AesCtrKey_t key_str3("RandomSixtyFourCharactersLaLaLaLaJust a bunch of letters, not 0x");
  ASSERT_FALSE(key_str2.IsValid());

  uint8_t key4[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};
                      //1234567890123456789012345678901234567890123456789012345678901234
  AesCtrKey_t key_str4("0102030405060708090A0B0C0D0E0F101112131415161718191a1b1c1d1e1f20");
  ASSERT_TRUE(key_str4.IsValid());
  ASSERT_TRUE(0 == memcmp(key4, key_str4.key, sizeof(key4)));
}

TEST(EnvEncrypt2_Key, Copy) {
  // assignment
  uint8_t data1[] = {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
                     0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                     0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
                     0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};
  AesCtrKey_t key1(data1, sizeof(data1)), key2;
  ASSERT_TRUE(key1.IsValid());
  ASSERT_FALSE(key2.IsValid());

  key2 = key1;
  ASSERT_TRUE(key1.IsValid());
  ASSERT_TRUE(key2.IsValid());
  ASSERT_TRUE(0 == memcmp(data1, key1.key, sizeof(data1)));
  ASSERT_TRUE(0 == memcmp(data1, key2.key, sizeof(data1)));

  // copy constructor
  uint8_t data3[] = {0x21, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
                     0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0x22, 0x20,
                     0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
                     0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};
  AesCtrKey_t key3(data3, sizeof(data3));
  ASSERT_TRUE(key3.IsValid());

  AesCtrKey_t key4(key3);
  ASSERT_TRUE(key3.IsValid());
  ASSERT_TRUE(key4.IsValid());
  ASSERT_TRUE(0 == memcmp(data3, key3.key, sizeof(data3)));
  ASSERT_TRUE(0 == memcmp(data3, key4.key, sizeof(data3)));
}

class EnvEncrypt2_Provider {};

class CipherStreamWrapper : public BlockAccessCipherStream {
public:
  Status TESTEncryptBlock(uint64_t blockIndex, char *data, char* scratch) {
    return EncryptBlock(blockIndex, data, scratch);
  }
};

TEST(EnvEncrypt2_Provider, NistExamples) {
  uint8_t key[] = {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
                   0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                   0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
                   0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};
  uint8_t init[] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
                    0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff};

  uint8_t plain1[] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                      0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
  uint8_t cypher1[] = {0x60, 0x1e, 0xc3, 0x13, 0x77, 0x57, 0x89, 0xa5,
                       0xb7, 0xa7, 0xf5, 0x04, 0xbb, 0xf3, 0xd2, 0x28};


  CTREncryptionProvider2 provider("NistExampleKey", key, sizeof(key));
  // only first 8 bytes of init taken in next call
  std::unique_ptr<BlockAccessCipherStream> stream(provider.CreateCipherStream2(1, init));

  uint64_t offset;
  memcpy((void*)&offset, (void*)&init[8], 8);
  uint8_t block[sizeof(plain1)];
  memcpy((void*)block, (void*)plain1, 16);
  CipherStreamWrapper * wrap = (CipherStreamWrapper *)stream.get();

  Status status = wrap->TESTEncryptBlock(offset, (char*)block, nullptr);
  ASSERT_TRUE(0 == memcmp(cypher1, block, sizeof(block)));
}

}  // namespace rocksdb
int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
