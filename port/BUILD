PLATFORM_DEFINES = select({
    "@toolchain//:is_target_linux": [
        "OS_LINUX",
        "ROCKSDB_PLATFORM_POSIX",
        "HAVE_SSE42",
        "ROCKSDB_LIB_IO_POSIX",
        "ROCKSDB_FALLOCATE_PRESENT",
        "ROCKSDB_MALLOC_USABLE_SIZE",
        "ROCKSDB_PTHREAD_ADAPTIVE_MUTEX",
        "ROCKSDB_RANGESYNC_PRESENT",
        "ROCKSDB_SCHED_GETCPU_PRESENT",
        "rocksdb_shared_EXPORTS",
        # Thread local support is disabled, as it appears to trigger an incompatibility with CentOS 7.
        # "ROCKSDB_SUPPORT_THREAD_LOCAL",
    ],
    "@toolchain//:is_target_osx": [
        "OS_MACOSX",
        "ROCKSDB_PLATFORM_POSIX",
        "HAVE_SSE42",
        "ROCKSDB_LIB_IO_POSIX",
        "rocksdb_shared_EXPORTS",
    ],
    "@toolchain//:is_target_windows": [
        "OS_WIN",
    ],
    "//conditions:default": [],
})

FEATURE_DEFINES = [
    "LZ4",
    "SNAPPY",
]

DEFAULT_DEFINES = PLATFORM_DEFINES + FEATURE_DEFINES

COMMON_HDRS = [
    "dirent.h",
    "likely.h",
    "port.h",
    "jemalloc_helper.h",
    "stack_trace.h",
    "sys_time.h",
    "util_logger.h",
]

PLATFORM_HDRS = select({
    "@toolchain//:is_target_linux" : [
        "port_posix.h",
    ],
    "@toolchain//:is_target_osx" : [
        "port_posix.h",
    ],
    "@toolchain//:is_target_windows" : glob(["win/*.h"]) + ["xpress.h"],
})

COMMON_SRCS = [
    "stack_trace.cc",
]

PLATFORM_SRCS = select({
    "@toolchain//:is_target_linux" : [
        "port_posix.cc",
    ],
    "@toolchain//:is_target_osx" : [
        "port_posix.cc",
    ],
    "@toolchain//:is_target_windows" : glob(["win/*.cc"]),
})

cc_library(
    name = "port",
    srcs = COMMON_SRCS + PLATFORM_SRCS,
    deps = [
        ":headers",
        "//util:headers",
    ],
    visibility = ["//visibility:public"],
    defines = DEFAULT_DEFINES,
)

cc_library(
    name = "headers",
    hdrs = COMMON_HDRS + PLATFORM_HDRS,
    deps = [
        "//env:headers",
    ],
    visibility = ["//visibility:public"],
    defines = DEFAULT_DEFINES,
)
