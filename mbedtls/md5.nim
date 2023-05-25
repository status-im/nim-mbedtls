{.used.}
import "csources"
import "platform_time"

{.compile: "./mbedtls/csources/library/md5.c".}

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}

type
  mbedtls_md5_context* {.bycopy.} = object
    private_total*: array[2, uint32]
    private_state*: array[4, uint32]
    private_buffer*: array[64, byte]

proc mbedtls_md5_init*(ctx: ptr mbedtls_md5_context) {.importc, cdecl.}
proc mbedtls_md5_free*(ctx: ptr mbedtls_md5_context) {.importc, cdecl.}
proc mbedtls_md5_clone*(dst: ptr mbedtls_md5_context;
                        src: ptr mbedtls_md5_context) {.importc, cdecl.}
proc mbedtls_md5_starts*(ctx: ptr mbedtls_md5_context): cint {.importc, cdecl.}
proc mbedtls_md5_update*(ctx: ptr mbedtls_md5_context; input: ptr byte;
                         ilen: uint): cint {.importc, cdecl.}
proc mbedtls_md5_finish*(ctx: ptr mbedtls_md5_context; output: array[16, byte]): cint {.
    importc, cdecl.}
proc mbedtls_internal_md5_process*(ctx: ptr mbedtls_md5_context;
                                   data: array[64, byte]): cint {.importc,
    cdecl.}
proc mbedtls_md5*(input: ptr byte; ilen: uint; output: array[16, byte]): cint {.
    importc, cdecl.}
proc mbedtls_md5_self_test*(verbose: cint): cint {.importc, cdecl.}
{.pop.}
