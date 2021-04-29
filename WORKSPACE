workspace(name = "rocksdb")
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

http_archive(
    name = "com_google_googletest",
    urls = ["https://github.com/google/googletest/archive/release-1.8.1.zip"],
    strip_prefix = "googletest-release-1.8.1",
#    sha256 = "927827c183d01734cc5cfef85e0ff3f5a92ffe6188e0d18e909c5efebf28a0c7",
)

http_archive(
    name = "com_google_snappy",
    urls = ["https://github.com/stardog-union/snappy/archive/stardog-develop-1.2.zip"],
    strip_prefix = "snappy-stardog-develop-1.2",
)

http_archive(
    name = "org_lz4",
    urls = ["https://github.com/lz4/lz4/archive/v1.8.2.zip"],
    strip_prefix = "lz4-1.8.2",
    build_file_content = """
cc_library(
    name = "lib",
    # We include the lz4.c as a header as lz4hc.c actually does #include "lz4.c".
    hdrs = glob(["lib/*.h"]) + ["lib/lz4.c"],
    includes = ["lib"],
    srcs = glob(["lib/*.c"]),
    visibility = ["//visibility:public"],
    strip_include_prefix = "lib",
)
    """
#    sha256 = "6df2bc7b830d4a23ca6f0a19a772fc0a61100f98baa843f9bbf873a80b6840d5",
)
