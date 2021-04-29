licenses(["notice"])

cc_library(
    name = "snappy",
    deps = ["@com_google_snappy//:snappy"],
    visibility = ["//visibility:public"],
)

cc_test(
    name = "compile_test",
    srcs = [
        "compile_test.cpp",
    ],
    deps = [
        ":snappy",
	"//third_party/gtest",
    ],
)

