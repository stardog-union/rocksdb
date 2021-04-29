def constrained_test(
        name,
        srcs = [],
        deps = [],
        copts = [],
        linkopts = [],
        defines = [],
        includes = [],
        visibility = ["//visibility:public"],
        tags = [],
        timeout = None):
    return native.cc_test(
        name = name,
        srcs = select({
            "//:tests_enabled_debug_mode": srcs,
            "//:tests_enabled_fastbuild_mode": srcs,
            "//conditions:default": [],
        }),
        deps = select({
            "//:tests_enabled_debug_mode": deps,
            "//:tests_enabled_fastbuild_mode": deps,
            "//conditions:default": ["//:empty_main"],
        }),
        copts = copts,
        linkopts = linkopts,
        defines = defines,
        includes = includes,
        visibility = visibility,
        tags = tags,
        timeout = timeout,
    )

def constrained_library(
        name,
        hdrs = [],
        srcs = [],
        deps = [],
        copts = [],
        linkopts = [],
        defines = [],
        includes = [],
        visibility = ["//visibility:public"],
        testonly = True):
    return native.cc_library(
        name = name,
        hdrs = select({
            "//:tests_enabled_debug_mode": hdrs,
            "//:tests_enabled_fastbuild_mode": hdrs,
            "//conditions:default": [],
        }),
        srcs = select({
            "//:tests_enabled_debug_mode": srcs,
            "//:tests_enabled_fastbuild_mode": srcs,
            "//conditions:default": [],
        }),
        deps = select({
            "//:tests_enabled_debug_mode": deps,
            "//:tests_enabled_fastbuild_mode": deps,
            "//conditions:default": ["//:empty_main"],
        }),
        copts = copts,
        linkopts = linkopts,
        defines = defines,
        includes = includes,
        visibility = visibility,
        testonly = testonly,
    )
