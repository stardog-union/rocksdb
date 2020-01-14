load("//:rocksdb.bzl", "constrained_test")

COMMON_HDRS = []

PLATFORM_HDRS = select({
    "//:linux" : [
        "allocator.h",
        "arena.h",
        "concurrent_arena.h",
        "jemalloc_nodump_allocator.h",
        "memory_allocator.h",
        "memory_usage.h"
    ],
    "//:osx" : [
        "allocator.h",
        "arena.h",
        "concurrent_arena.h",
        "jemalloc_nodump_allocator.h",
        "memory_allocator.h",
        "memory_usage.h"
    ],
    "//:windows" : [],
})

COMMON_SRCS = [
    "arena.cc",
    "concurrent_arena.cc",
    "jemalloc_nodump_allocator.cc"
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
    name = "memory",
    srcs = COMMON_SRCS + PLATFORM_SRCS,
    deps = [
        ":headers",
        "//include",
        "//options",
        "//logging:headers"
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
    name = "arena_test",
    srcs = ["arena_test.cc"],
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
