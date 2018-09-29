load("//:rocksdb.bzl", "constrained_test")

cc_library(
    name = "transactions",
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
	"//utilities/merge_operators/string_append:headers",
    ],
    visibility = ["//visibility:public"],
)

constrained_test(
    name = "optimistic_transaction_test",
    srcs = ["optimistic_transaction_test.cc"],
    deps = [
        ":transactions",
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
	"//utilities/backupable",
	"//utilities/checkpoint",
	"//utilities/merge_operators",
	"//utilities/merge_operators/string_append",
	"//utilities/options",
	"//utilities/ttl",
	"//utilities/write_batch_with_index",
    ],
)

constrained_test(
    name = "transaction_test",
    srcs = ["transaction_test.cc"],
    deps = [
        ":transactions",
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
	"//utilities/backupable",
	"//utilities/checkpoint",
	"//utilities/merge_operators",
	"//utilities/merge_operators/string_append",
	"//utilities/options",
	"//utilities/ttl",
	"//utilities/write_batch_with_index",
    ],
    timeout = "eternal",
    tags = ["manual"],
)

constrained_test(
    name = "write_prepared_transaction_test",
    srcs = ["write_prepared_transaction_test.cc"],
    deps = [
        ":transactions",
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
	"//utilities/write_batch_with_index",
    ],
    timeout = "eternal",
    tags = ["manual"],
)
