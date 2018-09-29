load("//:rocksdb.bzl", "constrained_test")

cc_library(
    name = "table_properties_collectors",
    hdrs = glob(["*.h"]),
    srcs = glob(["*.cc"], exclude=["*_test.cc"]),
    deps = [
        "//include",
    ],
    visibility = ["//visibility:public"],
)

constrained_test(
    name = "compact_on_deletion_collector_test",
    srcs = ["compact_on_deletion_collector_test.cc"],
    deps = [
        ":table_properties_collectors",
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
	"//utilities/ttl",
	"//utilities/transactions",
	"//utilities/write_batch_with_index",
    ],
)
