import "platform_time"

{.compile: "./mbedtls/csources/library/aria.c".}

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/csources/include".}
{.passc: "-I./mbedtls/csources/library".}

const
  MBEDTLS_ARIA_ENCRYPT* = 1
  MBEDTLS_ARIA_DECRYPT* = 0
  MBEDTLS_ARIA_BLOCKSIZE* = 16
  MBEDTLS_ARIA_MAX_ROUNDS* = 16
  MBEDTLS_ARIA_MAX_KEYSIZE* = 32
  MBEDTLS_ERR_ARIA_BAD_INPUT_DATA* = -0x0000005C
  MBEDTLS_ERR_ARIA_INVALID_INPUT_LENGTH* = -0x0000005E
type
  mbedtls_aria_context* {.bycopy.} = object
    private_nr*: byte
    private_rk*: array[16 + typeof(16)(1),
                       array[typeof(16)(16 / typeof(16)(4)), uint32]]

proc mbedtls_aria_init*(ctx: ptr mbedtls_aria_context) {.importc, cdecl.}
proc mbedtls_aria_free*(ctx: ptr mbedtls_aria_context) {.importc, cdecl.}
proc mbedtls_aria_setkey_enc*(ctx: ptr mbedtls_aria_context; key: ptr byte;
                              keybits: cuint): cint {.importc, cdecl.}
proc mbedtls_aria_setkey_dec*(ctx: ptr mbedtls_aria_context; key: ptr byte;
                              keybits: cuint): cint {.importc, cdecl.}
proc mbedtls_aria_crypt_ecb*(ctx: ptr mbedtls_aria_context;
                             input: array[16, byte]; output: array[16, byte]): cint {.
    importc, cdecl.}
proc mbedtls_aria_crypt_cbc*(ctx: ptr mbedtls_aria_context; mode: cint;
                             length: uint; iv: array[16, byte];
                             input: ptr byte; output: ptr byte): cint {.
    importc, cdecl.}
proc mbedtls_aria_crypt_cfb128*(ctx: ptr mbedtls_aria_context; mode: cint;
                                length: uint; iv_off: ptr uint;
                                iv: array[16, byte]; input: ptr byte;
                                output: ptr byte): cint {.importc, cdecl.}
proc mbedtls_aria_crypt_ctr*(ctx: ptr mbedtls_aria_context; length: uint;
                             nc_off: ptr uint; nonce_counter: array[16, byte];
                             stream_block: array[16, byte]; input: ptr byte;
                             output: ptr byte): cint {.importc, cdecl.}
proc mbedtls_aria_self_test*(verbose: cint): cint {.importc, cdecl.}
{.pop.}
