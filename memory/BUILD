load("//:rocksdb.bzl", "constrained_test")

cc_library(
    name = "memory",
    srcs = glob(["*.cc"], exclude=["*_test.cc"]),
    deps = [
        ":headers",
        "//logging:headers",
    ],
    visibility = ["//visibility:public"],
    alwayslink = 1,
)


cc_library(
    name = "headers",
    hdrs = glob(["*.h"], exclude=["*_test.h"]),
    deps = [
        "//port:headers",
        "//util:headers",
#        "//test_util",
        "//include",
    ],
    visibility = ["//visibility:public"],
    alwayslink = 1,
)
