#include "gtest/gtest.h"

namespace stardog {
  namespace {
    TEST(CompileTest, Compiles) {
      EXPECT_TRUE(true);
    }
  }
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
