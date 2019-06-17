licenses(["notice"])

cc_library(
    name = "gtest",
    deps = [
        "@com_google_googletest//:gtest",
    ],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "gtest_main",
    deps = [
        "@com_google_googletest//:gtest_main",
    ],
    visibility = ["//visibility:public"],
)

cc_test(
    name = "gtest_compile_test",
    srcs = [
        "compile_test.cpp",
    ],
    deps = [
        ":gtest",
    ],
)

cc_test(
    name = "gtest_main_compile_test",
    srcs = [
        "gtest_main_compile_test.cpp",
    ],
    deps = [
        ":gtest_main",
    ],
)
