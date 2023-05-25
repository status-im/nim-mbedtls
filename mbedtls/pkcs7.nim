import "csources"
import "asn1"
import "x509"
import "x509_crt"
import "x509_crl"
import "utils"

{.compile: "./mbedtls/csources/library/pkcs7.c".}

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}

defineEnum(mbedtls_pkcs7_type)

const
  MBEDTLS_ERR_PKCS7_INVALID_FORMAT* = -0x00005300
  MBEDTLS_ERR_PKCS7_FEATURE_UNAVAILABLE* = -0x00005380
  MBEDTLS_ERR_PKCS7_INVALID_VERSION* = -0x00005400
  MBEDTLS_ERR_PKCS7_INVALID_CONTENT_INFO* = -0x00005480
  MBEDTLS_ERR_PKCS7_INVALID_ALG* = -0x00005500
  MBEDTLS_ERR_PKCS7_INVALID_CERT* = -0x00005580
  MBEDTLS_ERR_PKCS7_INVALID_SIGNATURE* = -0x00005600
  MBEDTLS_ERR_PKCS7_INVALID_SIGNER_INFO* = -0x00005680
  MBEDTLS_ERR_PKCS7_BAD_INPUT_DATA* = -0x00005700
  MBEDTLS_ERR_PKCS7_ALLOC_FAILED* = -0x00005780
  MBEDTLS_ERR_PKCS7_VERIFY_FAIL* = -0x00005800
  MBEDTLS_ERR_PKCS7_CERT_DATE_INVALID* = -0x00005880
  MBEDTLS_PKCS7_SUPPORTED_VERSION* = 0x00000001
  MBEDTLS_PKCS7_NONE* = (0).mbedtls_pkcs7_type
  MBEDTLS_PKCS7_DATA* = (MBEDTLS_PKCS7_NONE + 1).mbedtls_pkcs7_type
  MBEDTLS_PKCS7_SIGNED_DATA* = (MBEDTLS_PKCS7_DATA + 1).mbedtls_pkcs7_type
  MBEDTLS_PKCS7_ENVELOPED_DATA* = (MBEDTLS_PKCS7_SIGNED_DATA + 1).mbedtls_pkcs7_type
  MBEDTLS_PKCS7_SIGNED_AND_ENVELOPED_DATA* = (MBEDTLS_PKCS7_ENVELOPED_DATA + 1).mbedtls_pkcs7_type
  MBEDTLS_PKCS7_DIGESTED_DATA* = (MBEDTLS_PKCS7_SIGNED_AND_ENVELOPED_DATA + 1).mbedtls_pkcs7_type
  MBEDTLS_PKCS7_ENCRYPTED_DATA* = (MBEDTLS_PKCS7_DIGESTED_DATA + 1).mbedtls_pkcs7_type
type
  mbedtls_pkcs7_buf* = mbedtls_asn1_buf
  mbedtls_pkcs7_name* = mbedtls_asn1_named_data
  mbedtls_pkcs7_sequence* = mbedtls_asn1_sequence
  mbedtls_pkcs7_signer_info* {.bycopy.} = object
    private_version*: cint
    private_serial*: mbedtls_x509_buf
    private_issuer*: mbedtls_x509_name
    private_issuer_raw*: mbedtls_x509_buf
    private_alg_identifier*: mbedtls_x509_buf
    private_sig_alg_identifier*: mbedtls_x509_buf
    private_sig*: mbedtls_x509_buf
    private_next*: ptr mbedtls_pkcs7_signer_info

  mbedtls_pkcs7_signed_data* {.bycopy.} = object
    private_version*: cint
    private_digest_alg_identifiers*: mbedtls_pkcs7_buf
    private_no_of_certs*: cint
    private_certs*: mbedtls_x509_crt
    private_no_of_crls*: cint
    private_crl*: mbedtls_x509_crl
    private_no_of_signers*: cint
    private_signers*: mbedtls_pkcs7_signer_info

  mbedtls_pkcs7* {.bycopy.} = object
    private_raw*: mbedtls_pkcs7_buf
    private_signed_data*: mbedtls_pkcs7_signed_data

proc mbedtls_pkcs7_init*(pkcs7: ptr mbedtls_pkcs7) {.importc, cdecl.}
proc mbedtls_pkcs7_parse_der*(pkcs7: ptr mbedtls_pkcs7; buf: ptr byte;
                              buflen: uint): cint {.importc, cdecl.}
proc mbedtls_pkcs7_signed_data_verify*(pkcs7: ptr mbedtls_pkcs7;
                                       cert: ptr mbedtls_x509_crt;
                                       data: ptr byte; datalen: uint): cint {.
    importc, cdecl.}
proc mbedtls_pkcs7_signed_hash_verify*(pkcs7: ptr mbedtls_pkcs7;
                                       cert: ptr mbedtls_x509_crt;
                                       hash: ptr byte; hashlen: uint): cint {.
    importc, cdecl.}
proc mbedtls_pkcs7_free*(pkcs7: ptr mbedtls_pkcs7) {.importc, cdecl.}
{.pop.}
