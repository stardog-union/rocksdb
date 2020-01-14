load("//:rocksdb.bzl", "constrained_test")

COMMON_HDRS = []

PLATFORM_HDRS = select({
    "//:linux" : [
        "delete_scheduler.h",
        "file_util.h",
        "filename.h",
        "sst_file_manager_impl.h"
    ],
    "//:osx" : [
        "delete_scheduler.h",
        "file_util.h",
        "filename.h",
        "sst_file_manager_impl.h"
    ],
    "//:windows" : [],
})

COMMON_SRCS = [
    "delete_scheduler.cc",
    "file_util.cc",
    "filename.cc",
    "sst_file_manager_impl.cc"
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
    name = "file",
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
    name = "delete_scheduler_test",
    srcs = ["delete_scheduler_test.cc"],
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
