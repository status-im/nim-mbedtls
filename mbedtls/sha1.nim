import "platform_time"

{.compile: "./mbedtls/csources/library/sha1.c".}

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/csources/include".}
{.passc: "-I./mbedtls/csources/library".}

const
  MBEDTLS_ERR_SHA1_BAD_INPUT_DATA* = -0x00000073
type
  mbedtls_sha1_context* {.bycopy.} = object
    private_total*: array[2, uint32]
    private_state*: array[5, uint32]
    private_buffer*: array[64, byte]

proc mbedtls_sha1_init*(ctx: ptr mbedtls_sha1_context) {.importc, cdecl.}
proc mbedtls_sha1_free*(ctx: ptr mbedtls_sha1_context) {.importc, cdecl.}
proc mbedtls_sha1_clone*(dst: ptr mbedtls_sha1_context;
                         src: ptr mbedtls_sha1_context) {.importc, cdecl.}
proc mbedtls_sha1_starts*(ctx: ptr mbedtls_sha1_context): cint {.importc, cdecl.}
proc mbedtls_sha1_update*(ctx: ptr mbedtls_sha1_context; input: ptr byte;
                          ilen: uint): cint {.importc, cdecl.}
proc mbedtls_sha1_finish*(ctx: ptr mbedtls_sha1_context;
                          output: array[20, byte]): cint {.importc, cdecl.}
proc mbedtls_internal_sha1_process*(ctx: ptr mbedtls_sha1_context;
                                    data: array[64, byte]): cint {.importc,
    cdecl.}
proc mbedtls_sha1*(input: ptr byte; ilen: uint; output: array[20, byte]): cint {.
    importc, cdecl.}
proc mbedtls_sha1_self_test*(verbose: cint): cint {.importc, cdecl.}
{.pop.}
