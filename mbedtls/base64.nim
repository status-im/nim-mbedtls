{.used.}
import "csources"
import "constant_time"

{.compile: "./mbedtls/csources/library/base64.c".}

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}

const
  MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL* = -0x0000002A
  MBEDTLS_ERR_BASE64_INVALID_CHARACTER* = -0x0000002C
proc mbedtls_base64_encode*(dst: ptr byte; dlen: uint; olen: ptr uint;
                            src: ptr byte; slen: uint): cint {.importc, cdecl.}
proc mbedtls_base64_decode*(dst: ptr byte; dlen: uint; olen: ptr uint;
                            src: ptr byte; slen: uint): cint {.importc, cdecl.}
proc mbedtls_base64_self_test*(verbose: cint): cint {.importc, cdecl.}
{.pop.}
