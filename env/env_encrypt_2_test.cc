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

class EnvEncrypt2_Sha1 {};

TEST(EnvEncrypt2_Sha1, Default) {
  Sha1Description_t desc;

  ASSERT_FALSE(desc.IsValid());
  for (size_t idx=0; idx<sizeof(desc.desc); ++idx) {
    ASSERT_TRUE('\0' == desc.desc[idx]);
  }
}



}  // namespace rocksdb
int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
