# Note - these "@//" need to come from Stardog requiring this
#        be built as a dependency, not standalone
DEPS = select({
    "@//:is_target_linux": [
    ],
    "@//:is_target_osx": [
        "@openssl_osx//:openssl_dev",
    ],
    "@//:is_target_windows": [
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
