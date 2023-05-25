{.used.}
import "csources"
import "cipher"

{.compile: "./mbedtls/csources/library/cmac.c".}

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}

const
  MBEDTLS_AES_BLOCK_SIZE* = 16
  MBEDTLS_DES3_BLOCK_SIZE* = 8
  MBEDTLS_CIPHER_BLKSIZE_MAX* = 16
type
  mbedtls_cmac_context_t* {.bycopy.} = object
    private_state*: array[16, byte]
    private_unprocessed_block*: array[16, byte]
    private_unprocessed_len*: uint

proc mbedtls_cipher_cmac_starts*(ctx: ptr mbedtls_cipher_context_t;
                                 key: ptr byte; keybits: uint): cint {.
    importc, cdecl.}
proc mbedtls_cipher_cmac_update*(ctx: ptr mbedtls_cipher_context_t;
                                 input: ptr byte; ilen: uint): cint {.importc,
    cdecl.}
proc mbedtls_cipher_cmac_finish*(ctx: ptr mbedtls_cipher_context_t;
                                 output: ptr byte): cint {.importc, cdecl.}
proc mbedtls_cipher_cmac_reset*(ctx: ptr mbedtls_cipher_context_t): cint {.
    importc, cdecl.}
proc mbedtls_cipher_cmac*(cipher_info: ptr mbedtls_cipher_info_t;
                          key: ptr byte; keylen: uint; input: ptr byte;
                          ilen: uint; output: ptr byte): cint {.importc, cdecl.}
proc mbedtls_aes_cmac_prf_128*(key: ptr byte; key_len: uint;
                               input: ptr byte; in_len: uint;
                               output: array[16, byte]): cint {.importc, cdecl.}
proc mbedtls_cmac_self_test*(verbose: cint): cint {.importc, cdecl.}
{.pop.}
