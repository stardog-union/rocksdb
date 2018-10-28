licenses(["notice"])

cc_library(
    name = "gtest",
    deps = [
        "@com_google_googletest//:gtest",
    ],
    visibility = ["//visibility:public"],
)

cc_test(
    name = "compile_test",
    srcs = [
        "compile_test.cpp",
    ],
    deps = [
        ":gtest",
    ],
)
