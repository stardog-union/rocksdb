load("//:rocksdb.bzl", "constrained_test")

cc_library(
    name = "string_append",
    srcs = glob(["*.cc"], exclude=["*_test.cc"]),
    deps = [
        ":headers",
        "//include",
        "//utilities:headers",
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
    name = "stringappend_test",
    srcs = ["stringappend_test.cc"],
    deps = [
        ":string_append",
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
	"//utilities/options",
	"//utilities/transactions",
	"//utilities/ttl",
	"//utilities/write_batch_with_index",
    ],
)
