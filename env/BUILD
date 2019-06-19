load("//:rocksdb.bzl", "constrained_library", "constrained_test")

COMMON_HDRS = []

PLATFORM_HDRS = select({
    "@toolchain//:is_target_linux" : [
        "env_chroot.h",
        "io_posix.h",
        "posix_logger.h",
    ],
    "@toolchain//:is_target_osx" : [
        "env_chroot.h",
        "io_posix.h",
        "posix_logger.h",
    ],
    "@toolchain//:is_target_windows" : [],
})

COMMON_SRCS = [
    "env.cc",
    "env_encryption.cc",
]

PLATFORM_SRCS = select({
    "@toolchain//:is_target_linux" : [
        "env_chroot.cc",
        "env_posix.cc",
        "io_posix.cc",
    ],
    "@toolchain//:is_target_osx" : [
        "env_chroot.cc",
        "env_posix.cc",
        "io_posix.cc",
    ],
    "@toolchain//:is_target_windows" : [],
})


DEFAULT_DEFINES = select({
    "@toolchain//:is_target_linux": ["ROCKSDB_PLATFORM_POSIX=1"],
    "@toolchain//:is_target_osx": ["ROCKSDB_PLATFORM_POSIX=1"],
    "//conditions:default": [],
})

cc_library(
    name = "env",
    srcs = COMMON_SRCS + PLATFORM_SRCS,
    deps = [
        ":headers",
        "//include",
        "//options",
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

constrained_library(
    name = "test_utils",
    hdrs = ["mock_env.h"],
    srcs = ["mock_env.cc"],
    deps = [
        "//db:headers",
        "//port:headers",
	"//third_party/gtest",
    ],
    visibility = ["//visibility:public"],
)

constrained_test(
    name = "env_basic_test",
    srcs = ["env_basic_test.cc"],
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
    name = "env_test",
    srcs = ["env_test.cc"],
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
    name = "mock_env_test",
    srcs = ["mock_env_test.cc"],
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
