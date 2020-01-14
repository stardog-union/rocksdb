load("//:rocksdb.bzl", "constrained_test")

COMMON_HDRS = []

PLATFORM_HDRS = select({
    "//:linux" : [
        "auto_roll_logger.h",
        "posix_logger.h",
        "event_logger.h",
        "log_buffer.h",
        "logging.h"
    ],
    "//:osx" : [
        "auto_roll_logger.h",
        "posix_logger.h",
        "event_logger.h",
        "log_buffer.h",
        "logging.h"
    ],
    "//:windows" : [],
})

COMMON_SRCS = [
    "auto_roll_logger.cc",
    "event_logger.cc",
    "log_buffer.cc"
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
    name = "logging",
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
    name = "auto_roll_logger_test",
    srcs = ["auto_roll_logger_test.cc"],
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

constrained_test(
    name = "event_logger_test",
    srcs = ["event_logger_test.cc"],
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
