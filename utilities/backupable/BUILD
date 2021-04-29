load("//:rocksdb.bzl", "constrained_test")

cc_library(
    name = "backupable",
    srcs = glob(["*.cc"], exclude=["*_test.cc"]),
    deps = [
        ":headers",
        "//db:headers",
        "//include",
        "//port:headers",
        "//util:headers",
	"//utilities/checkpoint:headers",
    ],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "headers",
    hdrs = glob(["*.h"]),
    deps = [
    ],
    visibility = ["//visibility:public"],
)

constrained_test(
    name = "test",
    srcs = glob(["*_test.cc"]),
    deps = [
        ":backupable",
        "//cache",
        "//db",
        "//env",
        "//memtable",
        "//monitoring",
        "//table",
        "//table:test_utils",
        "//third_party/gtest",
        "//util",
        "//util:test_utils",
	"//utilities/checkpoint",
	"//utilities/merge_operators",
	"//utilities/merge_operators/string_append",
	"//utilities/options",
	"//utilities/transactions",
	"//utilities/ttl",
	"//utilities/write_batch_with_index",
    ],
)
