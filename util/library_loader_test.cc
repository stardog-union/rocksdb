//  Copyright (c) 2011-present, Facebook, Inc.  All rights reserved.
//  This source code is licensed under both the GPLv2 (found in the
//  COPYING file in the root directory) and Apache 2.0 License
//  (found in the LICENSE.Apache file in the root directory).

#include <gtest/gtest.h>

#include "util/library_loader.h"

namespace rocksdb {

class UnixLibraryLoaderTest {};

TEST(UnixLibraryLoaderTest, Simple) {
  UnixLibraryLoader works("libm.so.6");
  UnixLibraryLoader fails("libbubbagump.so");

  ASSERT_TRUE(works.IsValid());
  ASSERT_FALSE(fails.IsValid());

  double (*floor)(double);

  floor = (double (*)(double))works.GetEntryPoint("floor");
  ASSERT_TRUE(nullptr != floor);
  ASSERT_TRUE(2.0 == (*floor)(2.2));

}

TEST(UnixLibraryLoaderTest, SSL) {
  UnixLibraryLoader ssl("libssl.so");
  UnixLibraryLoader crypto("libcrypto.so");

  ASSERT_TRUE(ssl.IsValid());
  ASSERT_TRUE(crypto.IsValid());

}


}  // namespace rocksdb

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
 return RUN_ALL_TESTS();
}
