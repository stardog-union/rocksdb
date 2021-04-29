load("//:rocksdb.bzl", "constrained_library", "constrained_test")

cc_library(
    name = "util",
    srcs = glob(["*.cc"], exclude=["log_write_bench.cc", "*_test.cc", "testharness.*", "*_test_env.*"]),
    deps = [
        ":headers",
        "//db:headers",
        "//include",
        "//options:headers",
        "//port",
    ],
    copts = ["-msse4.2", "-mpclmul"],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "headers",
    hdrs = glob(["*.h"], exclude=["testharness.*", "*_test_env.*"]),
    deps = [
        "//port:headers",
        "//third_party/lz4",
	    "//third_party/snappy",
    ],
    visibility = ["//visibility:public"],
)
