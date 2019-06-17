licenses(["notice"])

cc_library(
    name = "lz4",
    deps = ["@org_lz4//:lib"],
    visibility = ["//visibility:public"],
)

cc_test(
    name = "compile_test",
    srcs = [
        "compile_test.cpp",
    ],
    deps = [
        ":lz4",
	"//third_party/gtest:gtest_main",
    ],
)
