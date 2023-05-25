import "csources"
import "platform_time"

{.compile: "./mbedtls/csources/library/sha512.c".}

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}

const
  MBEDTLS_ERR_SHA512_BAD_INPUT_DATA* = -0x00000075
type
  mbedtls_sha512_context* {.bycopy.} = object
    private_total*: array[2, uint64]
    private_state*: array[8, uint64]
    private_buffer*: array[128, byte]
    private_is384*: cint

proc mbedtls_sha512_init*(ctx: ptr mbedtls_sha512_context) {.importc, cdecl.}
proc mbedtls_sha512_free*(ctx: ptr mbedtls_sha512_context) {.importc, cdecl.}
proc mbedtls_sha512_clone*(dst: ptr mbedtls_sha512_context;
                           src: ptr mbedtls_sha512_context) {.importc, cdecl.}
proc mbedtls_sha512_starts*(ctx: ptr mbedtls_sha512_context; is384: cint): cint {.
    importc, cdecl.}
proc mbedtls_sha512_update*(ctx: ptr mbedtls_sha512_context; input: ptr byte;
                            ilen: uint): cint {.importc, cdecl.}
proc mbedtls_sha512_finish*(ctx: ptr mbedtls_sha512_context; output: ptr byte): cint {.
    importc, cdecl.}
proc mbedtls_internal_sha512_process*(ctx: ptr mbedtls_sha512_context;
                                      data: array[128, byte]): cint {.importc,
    cdecl.}
proc mbedtls_sha512*(input: ptr byte; ilen: uint; output: ptr byte;
                     is384: cint): cint {.importc, cdecl.}
proc mbedtls_sha384_self_test*(verbose: cint): cint {.importc, cdecl.}
proc mbedtls_sha512_self_test*(verbose: cint): cint {.importc, cdecl.}
{.pop.}
