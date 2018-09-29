load("//:rocksdb.bzl", "constrained_test")

cc_library(
    name = "checkpoint",
    srcs = glob(["*.cc"], exclude=["*_test.cc"]),
    deps = [
        ":headers",
        "//db:headers",
        "//include",
        "//port:headers",
        "//util:headers",
	"//utilities/write_batch_with_index",
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
    name = "checkpoint_test",
    srcs = ["checkpoint_test.cc"],
    deps = [
        ":checkpoint",
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
	"//utilities/merge_operators",
	"//utilities/merge_operators/string_append",
	"//utilities/options",
	"//utilities/ttl",
	"//utilities/transactions",
	"//utilities/write_batch_with_index",
    ],
)
