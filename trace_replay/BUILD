load("//:rocksdb.bzl", "constrained_test")

COMMON_HDRS = []

PLATFORM_HDRS = select({
    "//:linux" : [
        "block_cache_tracer.h",
        "trace_replay.h"
    ],
    "//:osx" : [
        "block_cache_tracer.h",
        "trace_replay.h"
    ],
    "//:windows" : [],
})

COMMON_SRCS = [
    "block_cache_tracer.cc",
    "trace_replay.cc"
]

PLATFORM_SRCS = select({
    "//:linux" : [],
    "//:osx" : [],
    "//:windows" : [],
})

DEFAULT_DEFINES = select({
    "//:linux": ["ROCKSDB_PLATFORM_POSIX=1"],
    "//:osx": ["ROCKSDB_PLATFORM_POSIX=1"],
    "//conditions:default": [],
})

cc_library(
    name = "trace_replay",
    srcs = COMMON_SRCS + PLATFORM_SRCS,
    deps = [
        ":headers",
        "//include",
        "//options",
        "//memory:headers",
        "//file:headers",
    ],
    visibility = ["//visibility:public"],
    defines = DEFAULT_DEFINES,
)

cc_library(
    name = "headers",
    hdrs = COMMON_HDRS + PLATFORM_HDRS,
    visibility = ["//visibility:public"],
    defines = DEFAULT_DEFINES,
)

constrained_test(
    name = "block_cache_tracer_test",
    srcs = ["block_cache_tracer_test.cc"],
    deps = [
        ":env",
        ":test_utils",
        "//cache",
        "//db",
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
	"//utilities/write_batch_with_index",
    ],
)
