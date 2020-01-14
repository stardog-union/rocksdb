load("//:rocksdb.bzl", "constrained_test")

COMMON_HDRS = []

PLATFORM_HDRS = select({
    "//:linux" : [
        "fault_injection_test_env.h",
        "mock_time_env.h",
        "sync_point.h",
        "sync_point_impl.h",
        "testharness.h",
        "testutil.h",
        "transaction_test_util.h"
    ],
    "//:osx" : [
        "fault_injection_test_env.h",
        "mock_time_env.h",
        "sync_point.h",
        "sync_point_impl.h",
        "testharness.h",
        "testutil.h",
        "transaction_test_util.h"
    ],
    "//:windows" : [],
})

COMMON_SRCS = [
    "sync_point.cc",
    "sync_point_impl.cc",
    "testharness.cc",
    "testutil.cc"
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
    name = "test_util",
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
    deps = [
        "@com_google_googletest//:gtest",
        "@com_google_googletest//:gtest_main"
    ],
    defines = DEFAULT_DEFINES,
)
