import "platform_time"

{.compile: "./mbedtls/csources/library/sha256.c".}

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/csources/include".}
{.passc: "-I./mbedtls/csources/library".}

const
  MBEDTLS_ERR_SHA256_BAD_INPUT_DATA* = -0x00000074
type
  mbedtls_sha256_context* {.bycopy.} = object
    private_total*: array[2, uint32]
    private_state*: array[8, uint32]
    private_buffer*: array[64, byte]
    private_is224*: cint

proc mbedtls_sha256_init*(ctx: ptr mbedtls_sha256_context) {.importc, cdecl.}
proc mbedtls_sha256_free*(ctx: ptr mbedtls_sha256_context) {.importc, cdecl.}
proc mbedtls_sha256_clone*(dst: ptr mbedtls_sha256_context;
                           src: ptr mbedtls_sha256_context) {.importc, cdecl.}
proc mbedtls_sha256_starts*(ctx: ptr mbedtls_sha256_context; is224: cint): cint {.
    importc, cdecl.}
proc mbedtls_sha256_update*(ctx: ptr mbedtls_sha256_context; input: ptr byte;
                            ilen: uint): cint {.importc, cdecl.}
proc mbedtls_sha256_finish*(ctx: ptr mbedtls_sha256_context; output: ptr byte): cint {.
    importc, cdecl.}
proc mbedtls_internal_sha256_process*(ctx: ptr mbedtls_sha256_context;
                                      data: array[64, byte]): cint {.importc,
    cdecl.}
proc mbedtls_sha256*(input: ptr byte; ilen: uint; output: ptr byte;
                     is224: cint): cint {.importc, cdecl.}
proc mbedtls_sha224_self_test*(verbose: cint): cint {.importc, cdecl.}
proc mbedtls_sha256_self_test*(verbose: cint): cint {.importc, cdecl.}
{.pop.}
