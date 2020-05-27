DEPS = select({
    "@toolchain//:is_target_linux": [
    ],
    "@toolchain//:is_target_osx": [
        "@openssl_osx//:openssl_dev",
    ],
    "@toolchain//:is_target_windows": [
    ],
})

cc_library(
    name = "include",
    hdrs = glob(["**/*.h"]),
    visibility = ["//visibility:public"],
    deps = DEPS,
    strip_include_prefix = "/include",
)

cc_library(
    name = "with_extra_prefix",
    hdrs = glob(["**/*.h"]),
    deps = DEPS,
    visibility = ["//visibility:public"],
)
