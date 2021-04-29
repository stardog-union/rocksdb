load("//:rocksdb.bzl", "constrained_test")

PLATFORM_HDRS = select({
    "//:linux" : [ "posix_logger.h",],
    "//conditions:default" : [],
})

cc_library(
    name = "logging",
    srcs = ["auto_roll_logger.cc", "event_logger.cc", "log_buffer.cc"],
    deps = [
        ":headers",
        "//port",
        "//util:headers",
    ],
    visibility = ["//visibility:public"],
    alwayslink = 1,
)

cc_library(
    name = "headers",
    hdrs = ["auto_roll_logger.h", "env_logger.h", "event_logger.h", "log_buffer.h", "logging.h"] + PLATFORM_HDRS,
    deps = [
        "//port:headers",
        "//file:headers",
        "//memory:headers",
        "//util:headers",
        "//include",
    ],
    visibility = ["//visibility:public"],
)
