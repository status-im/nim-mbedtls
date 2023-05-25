{.used.}
import "csources"
import "md"

{.compile: "./mbedtls/csources/library/poly1305.c".}

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}

const
  MBEDTLS_ERR_POLY1305_BAD_INPUT_DATA* = -0x00000057
type
  mbedtls_poly1305_context* {.bycopy.} = object
    private_r*: array[4, uint32]
    private_s*: array[4, uint32]
    private_acc*: array[5, uint32]
    private_queue*: array[16, uint8]
    private_queue_len*: uint

proc mbedtls_poly1305_init*(ctx: ptr mbedtls_poly1305_context) {.importc, cdecl.}
proc mbedtls_poly1305_free*(ctx: ptr mbedtls_poly1305_context) {.importc, cdecl.}
proc mbedtls_poly1305_starts*(ctx: ptr mbedtls_poly1305_context;
                              key: array[32, byte]): cint {.importc, cdecl.}
proc mbedtls_poly1305_update*(ctx: ptr mbedtls_poly1305_context;
                              input: ptr byte; ilen: uint): cint {.importc,
    cdecl.}
proc mbedtls_poly1305_finish*(ctx: ptr mbedtls_poly1305_context;
                              mac: array[16, byte]): cint {.importc, cdecl.}
proc mbedtls_poly1305_mac*(key: array[32, byte]; input: ptr byte;
                           ilen: uint; mac: array[16, byte]): cint {.importc,
    cdecl.}
proc mbedtls_poly1305_self_test*(verbose: cint): cint {.importc, cdecl.}
{.pop.}
