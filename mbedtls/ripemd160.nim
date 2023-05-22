import "platform_time"

{.compile: "./mbedtls/csources/library/ripemd160.c".}

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/csources/include".}
{.passc: "-I./mbedtls/csources/library".}

type
  mbedtls_ripemd160_context* {.bycopy.} = object
    private_total*: array[2, uint32]
    private_state*: array[5, uint32]
    private_buffer*: array[64, byte]

proc mbedtls_ripemd160_init*(ctx: ptr mbedtls_ripemd160_context) {.importc,
    cdecl.}
proc mbedtls_ripemd160_free*(ctx: ptr mbedtls_ripemd160_context) {.importc,
    cdecl.}
proc mbedtls_ripemd160_clone*(dst: ptr mbedtls_ripemd160_context;
                              src: ptr mbedtls_ripemd160_context) {.importc,
    cdecl.}
proc mbedtls_ripemd160_starts*(ctx: ptr mbedtls_ripemd160_context): cint {.
    importc, cdecl.}
proc mbedtls_ripemd160_update*(ctx: ptr mbedtls_ripemd160_context;
                               input: ptr byte; ilen: uint): cint {.importc,
    cdecl.}
proc mbedtls_ripemd160_finish*(ctx: ptr mbedtls_ripemd160_context;
                               output: array[20, byte]): cint {.importc, cdecl.}
proc mbedtls_internal_ripemd160_process*(ctx: ptr mbedtls_ripemd160_context;
    data: array[64, byte]): cint {.importc, cdecl.}
proc mbedtls_ripemd160*(input: ptr byte; ilen: uint; output: array[20, byte]): cint {.
    importc, cdecl.}
proc mbedtls_ripemd160_self_test*(verbose: cint): cint {.importc, cdecl.}
{.pop.}
