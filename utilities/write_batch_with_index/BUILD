load("//:rocksdb.bzl", "constrained_test")

cc_library(
    name = "write_batch_with_index",
    srcs = glob(["*.cc"], exclude=["*_test.cc"]),
    deps = [
        ":headers",
        "//db:headers",
        "//include",
        "//memtable:headers",
    ],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "headers",
    hdrs = glob(["*.h"]),
    deps = [
        "//options:headers",
    ],
    visibility = ["//visibility:public"],
)

constrained_test(
    name = "test",
    srcs = glob(["*_test.cc"]),
    deps = [
        ":write_batch_with_index",
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
	"//utilities",
	"//utilities/backupable",
	"//utilities/checkpoint",
	"//utilities/merge_operators",
	"//utilities/merge_operators/string_append",
	"//utilities/options",
	"//utilities/transactions",
	"//utilities/ttl",
    ],
)
