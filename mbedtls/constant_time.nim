import "bignum"
# TODO: Remove bignum, it's not used in this file.

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/csources/include".}
{.passc: "-I./mbedtls/csources/library".}
proc mbedtls_ct_memcmp*(a: pointer; b: pointer; n: uint): cint {.importc, cdecl.}
{.pop.}
