{.used.}
import "csources"
import "bignum"

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}
proc mbedtls_ct_memcmp*(a: pointer; b: pointer; n: uint): cint {.importc, cdecl.}
{.pop.}
