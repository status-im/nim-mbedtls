import "asn1"
import "md"
import "cipher"
import "ctr_drbg"
import "rsa"

{.compile: "./mbedtls/csources/library/pkcs5.c".}

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/csources/include".}
{.passc: "-I./mbedtls/csources/library".}

const
  MBEDTLS_ERR_PKCS5_BAD_INPUT_DATA* = -0x00002F80
  MBEDTLS_ERR_PKCS5_INVALID_FORMAT* = -0x00002F00
  MBEDTLS_ERR_PKCS5_FEATURE_UNAVAILABLE* = -0x00002E80
  MBEDTLS_ERR_PKCS5_PASSWORD_MISMATCH* = -0x00002E00
  MBEDTLS_PKCS5_DECRYPT* = 0
  MBEDTLS_PKCS5_ENCRYPT* = 1
proc mbedtls_pkcs5_pbes2*(pbe_params: ptr mbedtls_asn1_buf; mode: cint;
                          pwd: ptr byte; pwdlen: uint; data: ptr byte;
                          datalen: uint; output: ptr byte): cint {.importc,
    cdecl.}
proc mbedtls_pkcs5_pbkdf2_hmac_ext*(md_type: mbedtls_md_type_t;
                                    password: ptr byte; plen: uint;
                                    salt: ptr byte; slen: uint;
                                    iteration_count: cuint; key_length: uint32;
                                    output: ptr byte): cint {.importc, cdecl.}
proc mbedtls_pkcs5_pbkdf2_hmac*(ctx: ptr mbedtls_md_context_t;
                                password: ptr byte; plen: uint;
                                salt: ptr byte; slen: uint;
                                iteration_count: cuint; key_length: uint32;
                                output: ptr byte): cint {.importc, cdecl.}
proc mbedtls_pkcs5_self_test*(verbose: cint): cint {.importc, cdecl.}
{.pop.}
