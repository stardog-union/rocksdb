cc_library(
    name = "test_util",
    deps = [":headers", "//db:headers"],
    srcs = glob(["*.cc"], exclude=["*_test.cc"]),
    visibility = ["//visibility:public"],
)

cc_library(
    name = "headers",
    deps = ["//include",
    "//env:headers",
    "//third_party/gtest"],
    hdrs = glob(["*.h"]),
    visibility = ["//visibility:public"],
)