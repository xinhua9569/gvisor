load("//tools:defs.bzl", "go_embed_data", "go_library")

package(licenses = ["notice"])

go_embed_data(
    name = "vdso_bin",
    src = "//vdso:vdso.so",
    package = "loader",
    var = "vdsoBin",
)

go_library(
    name = "loader",
    srcs = [
        "elf.go",
        "interpreter.go",
        "loader.go",
        "vdso.go",
        "vdso_state.go",
        ":vdso_bin",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi",
        "//pkg/abi/linux",
        "//pkg/binary",
        "//pkg/context",
        "//pkg/cpuid",
        "//pkg/log",
        "//pkg/rand",
        "//pkg/safemem",
        "//pkg/sentry/arch",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/anon",
        "//pkg/sentry/fs/fsutil",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/limits",
        "//pkg/sentry/memmap",
        "//pkg/sentry/mm",
        "//pkg/sentry/pgalloc",
        "//pkg/sentry/uniqueid",
        "//pkg/sentry/usage",
        "//pkg/syserr",
        "//pkg/syserror",
        "//pkg/usermem",
        "//pkg/waiter",
    ],
)
