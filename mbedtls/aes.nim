import "platform_time"

{.compile: "./mbedtls/csources/library/aes.c".}
{.compile: "./mbedtls/csources/library/aesni.c".}

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/csources/include".}
{.passc: "-I./mbedtls/csources/library".}

const
  MBEDTLS_AES_ENCRYPT* = 1
  MBEDTLS_AES_DECRYPT* = 0
  MBEDTLS_ERR_AES_INVALID_KEY_LENGTH* = -0x00000020
  MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH* = -0x00000022
  MBEDTLS_ERR_AES_BAD_INPUT_DATA* = -0x00000021
type
  mbedtls_aes_context* {.bycopy.} = object
    private_nr*: cint
    private_rk_offset*: uint
    private_buf*: array[68, uint32]

  mbedtls_aes_xts_context* {.bycopy.} = object
    private_crypt*: mbedtls_aes_context
    private_tweak*: mbedtls_aes_context

proc mbedtls_aes_init*(ctx: ptr mbedtls_aes_context) {.importc, cdecl.}
proc mbedtls_aes_free*(ctx: ptr mbedtls_aes_context) {.importc, cdecl.}
proc mbedtls_aes_xts_init*(ctx: ptr mbedtls_aes_xts_context) {.importc, cdecl.}
proc mbedtls_aes_xts_free*(ctx: ptr mbedtls_aes_xts_context) {.importc, cdecl.}
proc mbedtls_aes_setkey_enc*(ctx: ptr mbedtls_aes_context; key: ptr byte;
                             keybits: cuint): cint {.importc, cdecl.}
proc mbedtls_aes_setkey_dec*(ctx: ptr mbedtls_aes_context; key: ptr byte;
                             keybits: cuint): cint {.importc, cdecl.}
proc mbedtls_aes_xts_setkey_enc*(ctx: ptr mbedtls_aes_xts_context;
                                 key: ptr byte; keybits: cuint): cint {.
    importc, cdecl.}
proc mbedtls_aes_xts_setkey_dec*(ctx: ptr mbedtls_aes_xts_context;
                                 key: ptr byte; keybits: cuint): cint {.
    importc, cdecl.}
proc mbedtls_aes_crypt_ecb*(ctx: ptr mbedtls_aes_context; mode: cint;
                            input: array[16, byte]; output: array[16, byte]): cint {.
    importc, cdecl.}
proc mbedtls_aes_crypt_cbc*(ctx: ptr mbedtls_aes_context; mode: cint;
                            length: uint; iv: array[16, byte];
                            input: ptr byte; output: ptr byte): cint {.
    importc, cdecl.}
proc mbedtls_aes_crypt_xts*(ctx: ptr mbedtls_aes_xts_context; mode: cint;
                            length: uint; data_unit: array[16, byte];
                            input: ptr byte; output: ptr byte): cint {.
    importc, cdecl.}
proc mbedtls_aes_crypt_cfb128*(ctx: ptr mbedtls_aes_context; mode: cint;
                               length: uint; iv_off: ptr uint;
                               iv: array[16, byte]; input: ptr byte;
                               output: ptr byte): cint {.importc, cdecl.}
proc mbedtls_aes_crypt_cfb8*(ctx: ptr mbedtls_aes_context; mode: cint;
                             length: uint; iv: array[16, byte];
                             input: ptr byte; output: ptr byte): cint {.
    importc, cdecl.}
proc mbedtls_aes_crypt_ofb*(ctx: ptr mbedtls_aes_context; length: uint;
                            iv_off: ptr uint; iv: array[16, byte];
                            input: ptr byte; output: ptr byte): cint {.
    importc, cdecl.}
proc mbedtls_aes_crypt_ctr*(ctx: ptr mbedtls_aes_context; length: uint;
                            nc_off: ptr uint; nonce_counter: array[16, byte];
                            stream_block: array[16, byte]; input: ptr byte;
                            output: ptr byte): cint {.importc, cdecl.}
proc mbedtls_internal_aes_encrypt*(ctx: ptr mbedtls_aes_context;
                                   input: array[16, byte];
                                   output: array[16, byte]): cint {.importc,
    cdecl.}
proc mbedtls_internal_aes_decrypt*(ctx: ptr mbedtls_aes_context;
                                   input: array[16, byte];
                                   output: array[16, byte]): cint {.importc,
    cdecl.}
proc mbedtls_aes_self_test*(verbose: cint): cint {.importc, cdecl.}
{.pop.}
