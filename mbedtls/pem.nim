import "csources"
import "aes"
import "base64"
import "des"

{.compile: "./mbedtls/csources/library/pem.c".}

# proc 'mbedtls_pem_get_buffer' skipped - static inline procs cannot work with '--noHeader | -H'

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}

const
  MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT* = -0x00001080
  MBEDTLS_ERR_PEM_INVALID_DATA* = -0x00001100
  MBEDTLS_ERR_PEM_ALLOC_FAILED* = -0x00001180
  MBEDTLS_ERR_PEM_INVALID_ENC_IV* = -0x00001200
  MBEDTLS_ERR_PEM_UNKNOWN_ENC_ALG* = -0x00001280
  MBEDTLS_ERR_PEM_PASSWORD_REQUIRED* = -0x00001300
  MBEDTLS_ERR_PEM_PASSWORD_MISMATCH* = -0x00001380
  MBEDTLS_ERR_PEM_FEATURE_UNAVAILABLE* = -0x00001400
  MBEDTLS_ERR_PEM_BAD_INPUT_DATA* = -0x00001480
type
  mbedtls_pem_context* {.bycopy.} = object
    private_buf*: ptr byte
    private_buflen*: uint
    private_info*: ptr byte

proc mbedtls_pem_init*(ctx: ptr mbedtls_pem_context) {.importc, cdecl.}
proc mbedtls_pem_read_buffer*(ctx: ptr mbedtls_pem_context; header: cstring;
                              footer: cstring; data: ptr byte;
                              pwd: ptr byte; pwdlen: uint; use_len: ptr uint): cint {.
    importc, cdecl.}
proc mbedtls_pem_free*(ctx: ptr mbedtls_pem_context) {.importc, cdecl.}
proc mbedtls_pem_write_buffer*(header: cstring; footer: cstring;
                               der_data: ptr byte; der_len: uint;
                               buf: ptr byte; buf_len: uint; olen: ptr uint): cint {.
    importc, cdecl.}
{.pop.}
