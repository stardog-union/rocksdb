load("//:rocksdb.bzl", "constrained_test")

cc_library(
    name = "options",
    srcs = glob(["*.cc"], exclude=["*_test.cc"]),
    deps = [
        ":headers",
        "//db:headers",
        "//logging:headers",
        "//include",
        "//table:headers"
    ],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "headers",
    srcs = glob(["*.h"]),
    visibility = ["//visibility:public"],
)

constrained_test(
    name = "options_test",
    srcs = ["options_test.cc"],
    deps = [
        ":options",
        "//cache",
        "//db",
        "//env",
        "//memtable",
        "//monitoring",
        "//table",
        "//table:test_utils",
        "//third_party/gtest",
	"//util",
	"//utilities",
	"//utilities/backupable",
	"//utilities/checkpoint",
	"//utilities/leveldb_options",
	"//utilities/merge_operators",
	"//utilities/merge_operators/string_append",
	"//utilities/options",
	"//utilities/transactions",
	"//utilities/ttl",
	"//utilities/write_batch_with_index",
    ],
)

constrained_test(
    name = "options_settable_test",
    srcs = ["options_settable_test.cc"],
    deps = [
        ":options",
        "//cache",
        "//db",
        "//env",
        "//memtable",
        "//monitoring",
        "//table",
        "//table:test_utils",
        "//third_party/gtest",
	"//util",
	"//utilities",
	"//utilities/backupable",
	"//utilities/checkpoint",
	"//utilities/merge_operators",
	"//utilities/merge_operators/string_append",
	"//utilities/options",
	"//utilities/transactions",
	"//utilities/ttl",
	"//utilities/write_batch_with_index",
    ],
)
