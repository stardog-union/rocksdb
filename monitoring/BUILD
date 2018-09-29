load("//:rocksdb.bzl", "constrained_test")

cc_library(
    name = "monitoring",
    srcs = glob(["*.cc"], exclude=["*_test.cc"]),
    deps = [
        ":headers",
        "//db:headers",
        "//include",
        "//include:with_extra_prefix",
        "//options:headers",
        "//port:headers",
        "//table:headers",
        "//util:headers",
    ],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "headers",
    hdrs = glob(["*.h"]),
    deps = [
        "//include",
    ],
    visibility = ["//visibility:public"],
)

constrained_test(
    name = "histogram_test",
    srcs = ["histogram_test.cc"],
    deps = [
        ":monitoring",
        "//cache",
        "//db",
        "//env",
        "//memtable",
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
    name = "iostats_context_test",
    srcs = ["iostats_context_test.cc"],
    deps = [
        ":monitoring",
        "//cache",
        "//db",
        "//env",
        "//memtable",
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
    name = "statistics_test",
    srcs = ["statistics_test.cc"],
    deps = [
        ":monitoring",
        "//cache",
        "//db",
        "//env",
        "//memtable",
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
