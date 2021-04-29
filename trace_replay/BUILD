load("//:rocksdb.bzl", "constrained_test")

cc_library(
    name = "trace_replay",
    srcs = glob(["*.cc"], exclude=["*_test.cc"]),
    deps = [
        ":headers",
        "//db:headers",
    ],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "headers",
    srcs = glob(["*.h"]),
    deps = [
      "//include",
      "//monitoring:headers",
      "//port:headers",
    ],
    includes = ["//db"],
    visibility = ["//visibility:public"],
)
