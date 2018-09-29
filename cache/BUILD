load("//:rocksdb.bzl", "constrained_test")

cc_library(
    name = "cache",
    srcs = glob(["*.cc"], exclude=["cache_bench.cc", "*_test.cc"]),
    deps = [
        ":headers",
    ],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "headers",
    hdrs = glob(["*.h"]),
    deps = [
        "//include",
        "//port:headers",
        "//util:headers",
    ],
    visibility = ["//visibility:public"],
)

constrained_test(
    name = "cache_test",
    srcs = ["cache_test.cc"],
    deps = [
        ":cache",
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
	"//utilities/transactions",
	"//utilities/ttl",
	"//utilities/write_batch_with_index",
    ],
)

constrained_test(
    name = "lru_cache_test",
    srcs = ["lru_cache_test.cc"],
    deps = [
        ":cache",
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
	"//utilities/transactions",
	"//utilities/ttl",
	"//utilities/write_batch_with_index",
    ],
)
