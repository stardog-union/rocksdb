load("//:rocksdb.bzl", "constrained_test")

cc_library(
    name = "memtable",
    srcs = glob(["*.cc"], exclude=["memtablerep_bench.cc", "*_test.cc"]),
    deps = [
        ":headers",
        "//db:headers",
        "//include",
    ],
    visibility = ["//visibility:public"],
    alwayslink = 1,
)

cc_library(
    name = "headers",
    srcs = glob(["*.h"]),
    visibility = ["//visibility:public"],
)

constrained_test(
    name = "inlineskiplist_test",
    srcs = ["inlineskiplist_test.cc"],
    deps = [
        ":memtable",
        "//cache",
        "//db",
        "//env",
        "//monitoring",
        "//options",
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
    name = "skiplist_test",
    srcs = ["skiplist_test.cc"],
    deps = [
        ":memtable",
        "//cache",
        "//db",
        "//env",
        "//monitoring",
        "//options",
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
    name = "write_buffer_manager_test",
    srcs = ["write_buffer_manager_test.cc"],
    deps = [
        ":memtable",
        "//cache",
        "//db",
        "//env",
        "//monitoring",
        "//options",
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
