cc_library(
    name = "tools",
    deps = [
        ":headers",
    ],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "headers",
    hdrs = glob(["**/*.h"], exclude=["*_test.h"]),
    deps = [
        "//include",
        "//options:headers",
#        "//util:headers",
    ],
    visibility = ["//visibility:public"],
)
