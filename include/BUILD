cc_library(
    name = "include",
    hdrs = glob(["**/*.h"]),
    visibility = ["//visibility:public"],
    deps = [
        "@openssl_osx//:openssl_dev",
    ],
    strip_include_prefix = "/include",
)

cc_library(
    name = "with_extra_prefix",
    hdrs = glob(["**/*.h"]),
    deps = [
        "@openssl_osx//:openssl_dev",
    ],
    visibility = ["//visibility:public"],
)
