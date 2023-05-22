import "poly1305"
import "chacha20"
import "utils"

{.compile: "./mbedtls/csources/library/chachapoly.c".}

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/csources/include".}
{.passc: "-I./mbedtls/csources/library".}

defineEnum(mbedtls_chachapoly_mode_t)

const
  MBEDTLS_ERR_CHACHAPOLY_BAD_STATE* = -0x00000054
  MBEDTLS_ERR_CHACHAPOLY_AUTH_FAILED* = -0x00000056
  MBEDTLS_CHACHAPOLY_ENCRYPT* = (0).mbedtls_chachapoly_mode_t
  MBEDTLS_CHACHAPOLY_DECRYPT* = (MBEDTLS_CHACHAPOLY_ENCRYPT + 1).mbedtls_chachapoly_mode_t
type
  mbedtls_chachapoly_context* {.bycopy.} = object
    private_chacha20_ctx*: mbedtls_chacha20_context
    private_poly1305_ctx*: mbedtls_poly1305_context
    private_aad_len*: uint64
    private_ciphertext_len*: uint64
    private_state*: cint
    private_mode*: mbedtls_chachapoly_mode_t

proc mbedtls_chachapoly_init*(ctx: ptr mbedtls_chachapoly_context) {.importc,
    cdecl.}
proc mbedtls_chachapoly_free*(ctx: ptr mbedtls_chachapoly_context) {.importc,
    cdecl.}
proc mbedtls_chachapoly_setkey*(ctx: ptr mbedtls_chachapoly_context;
                                key: array[32, byte]): cint {.importc, cdecl.}
proc mbedtls_chachapoly_starts*(ctx: ptr mbedtls_chachapoly_context;
                                nonce: array[12, byte];
                                mode: mbedtls_chachapoly_mode_t): cint {.
    importc, cdecl.}
proc mbedtls_chachapoly_update_aad*(ctx: ptr mbedtls_chachapoly_context;
                                    aad: ptr byte; aad_len: uint): cint {.
    importc, cdecl.}
proc mbedtls_chachapoly_update*(ctx: ptr mbedtls_chachapoly_context; len: uint;
                                input: ptr byte; output: ptr byte): cint {.
    importc, cdecl.}
proc mbedtls_chachapoly_finish*(ctx: ptr mbedtls_chachapoly_context;
                                mac: array[16, byte]): cint {.importc, cdecl.}
proc mbedtls_chachapoly_encrypt_and_tag*(ctx: ptr mbedtls_chachapoly_context;
    length: uint; nonce: array[12, byte]; aad: ptr byte; aad_len: uint;
    input: ptr byte; output: ptr byte; tag: array[16, byte]): cint {.
    importc, cdecl.}
proc mbedtls_chachapoly_auth_decrypt*(ctx: ptr mbedtls_chachapoly_context;
                                      length: uint; nonce: array[12, byte];
                                      aad: ptr byte; aad_len: uint;
                                      tag: array[16, byte]; input: ptr byte;
                                      output: ptr byte): cint {.importc, cdecl.}
proc mbedtls_chachapoly_self_test*(verbose: cint): cint {.importc, cdecl.}
{.pop.}
