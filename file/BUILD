
cc_library(
    name = "file",
    srcs = glob(["*.cc"], exclude=["*_test.cc"]),
    deps = [ ":headers"],
    visibility = ["//visibility:public"],
    alwayslink = 1,
)

cc_library(
    name = "headers",
    hdrs = glob(["*.h"], exclude=["*_test.h"]),
    deps = [
        "//env:headers",
        "//port:headers",
        "//options:headers",
        "//test_util:headers",
        "//util:headers",
        "//include",
    ],
    visibility = ["//visibility:public"],
    includes = ["@//db"],
    alwayslink = 1,
)
