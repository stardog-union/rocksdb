cc_library(
    name = "merge_operators",
    srcs = glob(["*.cc"], exclude=["*_test.cc"]),
    deps = [
        ":headers",
        "//db:headers",
        "//include",
        "//port:headers",
        "//util:headers",
	"//utilities/checkpoint:headers",
    ],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "headers",
    hdrs = glob(["*.h"]),
    deps = [
    ],
    visibility = ["//visibility:public"],
)
