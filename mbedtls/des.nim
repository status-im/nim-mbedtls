{.used.}
import "csources"
import "platform_time"

{.compile: "./mbedtls/csources/library/des.c".}

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}

const
  MBEDTLS_DES_ENCRYPT* = 1
  MBEDTLS_DES_DECRYPT* = 0
  MBEDTLS_ERR_DES_INVALID_INPUT_LENGTH* = -0x00000032
  MBEDTLS_DES_KEY_SIZE* = 8
type
  mbedtls_des_context* {.bycopy.} = object
    private_sk*: array[32, uint32]

  mbedtls_des3_context* {.bycopy.} = object
    private_sk*: array[96, uint32]

proc mbedtls_des_init*(ctx: ptr mbedtls_des_context) {.importc, cdecl.}
proc mbedtls_des_free*(ctx: ptr mbedtls_des_context) {.importc, cdecl.}
proc mbedtls_des3_init*(ctx: ptr mbedtls_des3_context) {.importc, cdecl.}
proc mbedtls_des3_free*(ctx: ptr mbedtls_des3_context) {.importc, cdecl.}
proc mbedtls_des_key_set_parity*(key: array[8, byte]) {.importc, cdecl.}
proc mbedtls_des_key_check_key_parity*(key: array[8, byte]): cint {.importc,
    cdecl.}
proc mbedtls_des_key_check_weak*(key: array[8, byte]): cint {.importc, cdecl.}
proc mbedtls_des_setkey_enc*(ctx: ptr mbedtls_des_context; key: array[8, byte]): cint {.
    importc, cdecl.}
proc mbedtls_des_setkey_dec*(ctx: ptr mbedtls_des_context; key: array[8, byte]): cint {.
    importc, cdecl.}
proc mbedtls_des3_set2key_enc*(ctx: ptr mbedtls_des3_context;
                               key: array[8 * typeof(8)(2), byte]): cint {.
    importc, cdecl.}
proc mbedtls_des3_set2key_dec*(ctx: ptr mbedtls_des3_context;
                               key: array[8 * typeof(8)(2), byte]): cint {.
    importc, cdecl.}
proc mbedtls_des3_set3key_enc*(ctx: ptr mbedtls_des3_context;
                               key: array[8 * typeof(8)(3), byte]): cint {.
    importc, cdecl.}
proc mbedtls_des3_set3key_dec*(ctx: ptr mbedtls_des3_context;
                               key: array[8 * typeof(8)(3), byte]): cint {.
    importc, cdecl.}
proc mbedtls_des_crypt_ecb*(ctx: ptr mbedtls_des_context;
                            input: array[8, byte]; output: array[8, byte]): cint {.
    importc, cdecl.}
proc mbedtls_des_crypt_cbc*(ctx: ptr mbedtls_des_context; mode: cint;
                            length: uint; iv: array[8, byte];
                            input: ptr byte; output: ptr byte): cint {.
    importc, cdecl.}
proc mbedtls_des3_crypt_ecb*(ctx: ptr mbedtls_des3_context;
                             input: array[8, byte]; output: array[8, byte]): cint {.
    importc, cdecl.}
proc mbedtls_des3_crypt_cbc*(ctx: ptr mbedtls_des3_context; mode: cint;
                             length: uint; iv: array[8, byte];
                             input: ptr byte; output: ptr byte): cint {.
    importc, cdecl.}
proc mbedtls_des_setkey*(SK: array[32, uint32]; key: array[8, byte]) {.
    importc, cdecl.}
proc mbedtls_des_self_test*(verbose: cint): cint {.importc, cdecl.}
{.pop.}
