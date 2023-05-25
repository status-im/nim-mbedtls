import "csources"
{.compile: "./mbedtls/csources/library/version.c".}
{.compile: "./mbedtls/csources/library/version_features.c".}

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}

proc mbedtls_version_get_number*(): cuint {.importc, cdecl.}
proc mbedtls_version_get_string*(string: cstring) {.importc, cdecl.}
proc mbedtls_version_get_string_full*(string: cstring) {.importc, cdecl.}
proc mbedtls_version_check_feature*(feature: cstring): cint {.importc, cdecl.}
{.pop.}
