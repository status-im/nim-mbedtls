{.used.}
import "csources"
import "platform_time"

{.compile: "./mbedtls/csources/library/chacha20.c".}

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}

const
  MBEDTLS_ERR_CHACHA20_BAD_INPUT_DATA* = -0x00000051
type
  mbedtls_chacha20_context* {.bycopy.} = object
    private_state*: array[16, uint32]
    private_keystream8*: array[64, uint8]
    private_keystream_bytes_used*: uint

proc mbedtls_chacha20_init*(ctx: ptr mbedtls_chacha20_context) {.importc, cdecl.}
proc mbedtls_chacha20_free*(ctx: ptr mbedtls_chacha20_context) {.importc, cdecl.}
proc mbedtls_chacha20_setkey*(ctx: ptr mbedtls_chacha20_context;
                              key: array[32, byte]): cint {.importc, cdecl.}
proc mbedtls_chacha20_starts*(ctx: ptr mbedtls_chacha20_context;
                              nonce: array[12, byte]; counter: uint32): cint {.
    importc, cdecl.}
proc mbedtls_chacha20_update*(ctx: ptr mbedtls_chacha20_context; size: uint;
                              input: ptr byte; output: ptr byte): cint {.
    importc, cdecl.}
proc mbedtls_chacha20_crypt*(key: array[32, byte]; nonce: array[12, byte];
                             counter: uint32; size: uint; input: ptr byte;
                             output: ptr byte): cint {.importc, cdecl.}
proc mbedtls_chacha20_self_test*(verbose: cint): cint {.importc, cdecl.}
{.pop.}
