import "platform_time"

{.compile: "./mbedtls/csources/library/camellia.c".}

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/csources/include".}
{.passc: "-I./mbedtls/csources/library".}

const
  MBEDTLS_CAMELLIA_ENCRYPT* = 1
  MBEDTLS_CAMELLIA_DECRYPT* = 0
  MBEDTLS_ERR_CAMELLIA_BAD_INPUT_DATA* = -0x00000024
  MBEDTLS_ERR_CAMELLIA_INVALID_INPUT_LENGTH* = -0x00000026
type
  mbedtls_camellia_context* {.bycopy.} = object
    private_nr*: cint
    private_rk*: array[68, uint32]

proc mbedtls_camellia_init*(ctx: ptr mbedtls_camellia_context) {.importc, cdecl.}
proc mbedtls_camellia_free*(ctx: ptr mbedtls_camellia_context) {.importc, cdecl.}
proc mbedtls_camellia_setkey_enc*(ctx: ptr mbedtls_camellia_context;
                                  key: ptr byte; keybits: cuint): cint {.
    importc, cdecl.}
proc mbedtls_camellia_setkey_dec*(ctx: ptr mbedtls_camellia_context;
                                  key: ptr byte; keybits: cuint): cint {.
    importc, cdecl.}
proc mbedtls_camellia_crypt_ecb*(ctx: ptr mbedtls_camellia_context; mode: cint;
                                 input: array[16, byte];
                                 output: array[16, byte]): cint {.importc,
    cdecl.}
proc mbedtls_camellia_crypt_cbc*(ctx: ptr mbedtls_camellia_context; mode: cint;
                                 length: uint; iv: array[16, byte];
                                 input: ptr byte; output: ptr byte): cint {.
    importc, cdecl.}
proc mbedtls_camellia_crypt_cfb128*(ctx: ptr mbedtls_camellia_context;
                                    mode: cint; length: uint; iv_off: ptr uint;
                                    iv: array[16, byte]; input: ptr byte;
                                    output: ptr byte): cint {.importc, cdecl.}
proc mbedtls_camellia_crypt_ctr*(ctx: ptr mbedtls_camellia_context;
                                 length: uint; nc_off: ptr uint;
                                 nonce_counter: array[16, byte];
                                 stream_block: array[16, byte];
                                 input: ptr byte; output: ptr byte): cint {.
    importc, cdecl.}
proc mbedtls_camellia_self_test*(verbose: cint): cint {.importc, cdecl.}
{.pop.}
