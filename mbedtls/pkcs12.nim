import "csources"
import "md"
import "platform_time"
import "cipher"
import "asn1"
import "ctr_drbg"
import "hash_info"

{.compile: "./mbedtls/csources/library/pkcs12.c".}

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}

const
  MBEDTLS_ERR_PKCS12_BAD_INPUT_DATA* = -0x00001F80
  MBEDTLS_ERR_PKCS12_FEATURE_UNAVAILABLE* = -0x00001F00
  MBEDTLS_ERR_PKCS12_PBE_INVALID_FORMAT* = -0x00001E80
  MBEDTLS_ERR_PKCS12_PASSWORD_MISMATCH* = -0x00001E00
  MBEDTLS_PKCS12_DERIVE_KEY* = 1
  MBEDTLS_PKCS12_DERIVE_IV* = 2
  MBEDTLS_PKCS12_DERIVE_MAC_KEY* = 3
  MBEDTLS_PKCS12_PBE_DECRYPT* = 0
  MBEDTLS_PKCS12_PBE_ENCRYPT* = 1
proc mbedtls_pkcs12_pbe*(pbe_params: ptr mbedtls_asn1_buf; mode: cint;
                         cipher_type: mbedtls_cipher_type_t;
                         md_type: mbedtls_md_type_t; pwd: ptr byte;
                         pwdlen: uint; input: ptr byte; len: uint;
                         output: ptr byte): cint {.importc, cdecl.}
proc mbedtls_pkcs12_derivation*(data: ptr byte; datalen: uint;
                                pwd: ptr byte; pwdlen: uint; salt: ptr byte;
                                saltlen: uint; mbedtls_md: mbedtls_md_type_t;
                                id: cint; iterations: cint): cint {.importc,
    cdecl.}
{.pop.}
