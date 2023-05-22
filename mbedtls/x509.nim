import "asn1"
import "pk"
import "md"

{.compile: "./mbedtls/csources/library/x509.c".}
{.compile: "./mbedtls/csources/library/x509_create.c".}

# const 'MBEDTLS_X509_EXT_AUTHORITY_KEY_IDENTIFIER' has unsupported value 'MBEDTLS_OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER'
# const 'MBEDTLS_X509_EXT_SUBJECT_KEY_IDENTIFIER' has unsupported value 'MBEDTLS_OID_X509_EXT_SUBJECT_KEY_IDENTIFIER'
# const 'MBEDTLS_X509_EXT_KEY_USAGE' has unsupported value 'MBEDTLS_OID_X509_EXT_KEY_USAGE'
# const 'MBEDTLS_X509_EXT_CERTIFICATE_POLICIES' has unsupported value 'MBEDTLS_OID_X509_EXT_CERTIFICATE_POLICIES'
# const 'MBEDTLS_X509_EXT_POLICY_MAPPINGS' has unsupported value 'MBEDTLS_OID_X509_EXT_POLICY_MAPPINGS'
# const 'MBEDTLS_X509_EXT_SUBJECT_ALT_NAME' has unsupported value 'MBEDTLS_OID_X509_EXT_SUBJECT_ALT_NAME'
# const 'MBEDTLS_X509_EXT_ISSUER_ALT_NAME' has unsupported value 'MBEDTLS_OID_X509_EXT_ISSUER_ALT_NAME'
# const 'MBEDTLS_X509_EXT_SUBJECT_DIRECTORY_ATTRS' has unsupported value 'MBEDTLS_OID_X509_EXT_SUBJECT_DIRECTORY_ATTRS'
# const 'MBEDTLS_X509_EXT_BASIC_CONSTRAINTS' has unsupported value 'MBEDTLS_OID_X509_EXT_BASIC_CONSTRAINTS'
# const 'MBEDTLS_X509_EXT_NAME_CONSTRAINTS' has unsupported value 'MBEDTLS_OID_X509_EXT_NAME_CONSTRAINTS'
# const 'MBEDTLS_X509_EXT_POLICY_CONSTRAINTS' has unsupported value 'MBEDTLS_OID_X509_EXT_POLICY_CONSTRAINTS'
# const 'MBEDTLS_X509_EXT_EXTENDED_KEY_USAGE' has unsupported value 'MBEDTLS_OID_X509_EXT_EXTENDED_KEY_USAGE'
# const 'MBEDTLS_X509_EXT_CRL_DISTRIBUTION_POINTS' has unsupported value 'MBEDTLS_OID_X509_EXT_CRL_DISTRIBUTION_POINTS'
# const 'MBEDTLS_X509_EXT_INIHIBIT_ANYPOLICY' has unsupported value 'MBEDTLS_OID_X509_EXT_INIHIBIT_ANYPOLICY'
# const 'MBEDTLS_X509_EXT_FRESHEST_CRL' has unsupported value 'MBEDTLS_OID_X509_EXT_FRESHEST_CRL'
# const 'MBEDTLS_X509_EXT_NS_CERT_TYPE' has unsupported value 'MBEDTLS_OID_X509_EXT_NS_CERT_TYPE'
# proc 'mbedtls_x509_dn_get_next' skipped - static inline procs cannot work with '--noHeader | -H'
# const 'MBEDTLS_X509_SAFE_SNPRINTF' has unsupported value 'do { if (ret < 0 || (size_t) ret >= n) return MBEDTLS_ERR_X509_BUFFER_TOO_SMALL; n -= (size_t) ret; p += (size_t) ret; } while (0)'

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/csources/include".}
{.passc: "-I./mbedtls/csources/library".}

const
  MBEDTLS_X509_MAX_INTERMEDIATE_CA* = 8
  MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE* = -0x00002080
  MBEDTLS_ERR_X509_UNKNOWN_OID* = -0x00002100
  MBEDTLS_ERR_X509_INVALID_FORMAT* = -0x00002180
  MBEDTLS_ERR_X509_INVALID_VERSION* = -0x00002200
  MBEDTLS_ERR_X509_INVALID_SERIAL* = -0x00002280
  MBEDTLS_ERR_X509_INVALID_ALG* = -0x00002300
  MBEDTLS_ERR_X509_INVALID_NAME* = -0x00002380
  MBEDTLS_ERR_X509_INVALID_DATE* = -0x00002400
  MBEDTLS_ERR_X509_INVALID_SIGNATURE* = -0x00002480
  MBEDTLS_ERR_X509_INVALID_EXTENSIONS* = -0x00002500
  MBEDTLS_ERR_X509_UNKNOWN_VERSION* = -0x00002580
  MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG* = -0x00002600
  MBEDTLS_ERR_X509_SIG_MISMATCH* = -0x00002680
  MBEDTLS_ERR_X509_CERT_VERIFY_FAILED* = -0x00002700
  MBEDTLS_ERR_X509_CERT_UNKNOWN_FORMAT* = -0x00002780
  MBEDTLS_ERR_X509_BAD_INPUT_DATA* = -0x00002800
  MBEDTLS_ERR_X509_ALLOC_FAILED* = -0x00002880
  MBEDTLS_ERR_X509_FILE_IO_ERROR* = -0x00002900
  MBEDTLS_ERR_X509_BUFFER_TOO_SMALL* = -0x00002980
  MBEDTLS_ERR_X509_FATAL_ERROR* = -0x00003000
  MBEDTLS_X509_BADCERT_EXPIRED* = 0x00000001
  MBEDTLS_X509_BADCERT_REVOKED* = 0x00000002
  MBEDTLS_X509_BADCERT_CN_MISMATCH* = 0x00000004
  MBEDTLS_X509_BADCERT_NOT_TRUSTED* = 0x00000008
  MBEDTLS_X509_BADCRL_NOT_TRUSTED* = 0x00000010
  MBEDTLS_X509_BADCRL_EXPIRED* = 0x00000020
  MBEDTLS_X509_BADCERT_MISSING* = 0x00000040
  MBEDTLS_X509_BADCERT_SKIP_VERIFY* = 0x00000080
  MBEDTLS_X509_BADCERT_OTHER* = 0x00000100
  MBEDTLS_X509_BADCERT_FUTURE* = 0x00000200
  MBEDTLS_X509_BADCRL_FUTURE* = 0x00000400
  MBEDTLS_X509_BADCERT_KEY_USAGE* = 0x00000800
  MBEDTLS_X509_BADCERT_EXT_KEY_USAGE* = 0x00001000
  MBEDTLS_X509_BADCERT_NS_CERT_TYPE* = 0x00002000
  MBEDTLS_X509_BADCERT_BAD_MD* = 0x00004000
  MBEDTLS_X509_BADCERT_BAD_PK* = 0x00008000
  MBEDTLS_X509_BADCERT_BAD_KEY* = 0x00010000
  MBEDTLS_X509_BADCRL_BAD_MD* = 0x00020000
  MBEDTLS_X509_BADCRL_BAD_PK* = 0x00040000
  MBEDTLS_X509_BADCRL_BAD_KEY* = 0x00080000
  MBEDTLS_X509_SAN_OTHER_NAME* = 0
  MBEDTLS_X509_SAN_RFC822_NAME* = 1
  MBEDTLS_X509_SAN_DNS_NAME* = 2
  MBEDTLS_X509_SAN_X400_ADDRESS_NAME* = 3
  MBEDTLS_X509_SAN_DIRECTORY_NAME* = 4
  MBEDTLS_X509_SAN_EDI_PARTY_NAME* = 5
  MBEDTLS_X509_SAN_UNIFORM_RESOURCE_IDENTIFIER* = 6
  MBEDTLS_X509_SAN_IP_ADDRESS* = 7
  MBEDTLS_X509_SAN_REGISTERED_ID* = 8
  MBEDTLS_X509_KU_DIGITAL_SIGNATURE* = (0x00000080)
  MBEDTLS_X509_KU_NON_REPUDIATION* = (0x00000040)
  MBEDTLS_X509_KU_KEY_ENCIPHERMENT* = (0x00000020)
  MBEDTLS_X509_KU_DATA_ENCIPHERMENT* = (0x00000010)
  MBEDTLS_X509_KU_KEY_AGREEMENT* = (0x00000008)
  MBEDTLS_X509_KU_KEY_CERT_SIGN* = (0x00000004)
  MBEDTLS_X509_KU_CRL_SIGN* = (0x00000002)
  MBEDTLS_X509_KU_ENCIPHER_ONLY* = (0x00000001)
  MBEDTLS_X509_KU_DECIPHER_ONLY* = (0x00008000)
  MBEDTLS_X509_NS_CERT_TYPE_SSL_CLIENT* = (0x00000080)
  MBEDTLS_X509_NS_CERT_TYPE_SSL_SERVER* = (0x00000040)
  MBEDTLS_X509_NS_CERT_TYPE_EMAIL* = (0x00000020)
  MBEDTLS_X509_NS_CERT_TYPE_OBJECT_SIGNING* = (0x00000010)
  MBEDTLS_X509_NS_CERT_TYPE_RESERVED* = (0x00000008)
  MBEDTLS_X509_NS_CERT_TYPE_SSL_CA* = (0x00000004)
  MBEDTLS_X509_NS_CERT_TYPE_EMAIL_CA* = (0x00000002)
  MBEDTLS_X509_NS_CERT_TYPE_OBJECT_SIGNING_CA* = (0x00000001)
  MBEDTLS_X509_FORMAT_DER* = 1
  MBEDTLS_X509_FORMAT_PEM* = 2
  MBEDTLS_X509_MAX_DN_NAME_SIZE* = 256
type
  mbedtls_x509_buf* = mbedtls_asn1_buf
  mbedtls_x509_bitstring* = mbedtls_asn1_bitstring
  mbedtls_x509_name* = mbedtls_asn1_named_data
  mbedtls_x509_sequence* = mbedtls_asn1_sequence
  mbedtls_x509_time* {.bycopy.} = object
    year*: cint
    mon*: cint
    day*: cint
    hour*: cint
    min*: cint
    sec*: cint

  Type_x509h1* {.bycopy.} = object
    oid*: mbedtls_x509_buf
    val*: mbedtls_x509_buf

  Union_x509h1* {.union, bycopy.} = object
    hardware_module_name*: Type_x509h1

  mbedtls_x509_san_other_name* {.bycopy.} = object
    type_id*: mbedtls_x509_buf
    value*: Union_x509h1

  Union_x509h2* {.union, bycopy.} = object
    other_name*: mbedtls_x509_san_other_name
    directory_name*: mbedtls_x509_name
    unstructured_name*: mbedtls_x509_buf

  mbedtls_x509_subject_alternative_name* {.bycopy.} = object
    `type`*: cint
    san*: Union_x509h2

proc mbedtls_x509_dn_gets*(buf: cstring; size: uint; dn: ptr mbedtls_x509_name): cint {.
    importc, cdecl.}
proc mbedtls_x509_serial_gets*(buf: cstring; size: uint;
                               serial: ptr mbedtls_x509_buf): cint {.importc,
    cdecl.}
proc mbedtls_x509_time_is_past*(to: ptr mbedtls_x509_time): cint {.importc,
    cdecl.}
proc mbedtls_x509_time_is_future*(`from`: ptr mbedtls_x509_time): cint {.
    importc, cdecl.}
proc mbedtls_x509_parse_subject_alt_name*(san_buf: ptr mbedtls_x509_buf;
    san: ptr mbedtls_x509_subject_alternative_name): cint {.importc, cdecl.}
proc mbedtls_x509_free_subject_alt_name*(
    san: ptr mbedtls_x509_subject_alternative_name) {.importc, cdecl.}
proc mbedtls_x509_get_name*(p: ptr ptr byte; `end`: ptr byte;
                            cur: ptr mbedtls_x509_name): cint {.importc, cdecl.}
proc mbedtls_x509_get_alg_null*(p: ptr ptr byte; `end`: ptr byte;
                                alg: ptr mbedtls_x509_buf): cint {.importc,
    cdecl.}
proc mbedtls_x509_get_alg*(p: ptr ptr byte; `end`: ptr byte;
                           alg: ptr mbedtls_x509_buf;
                           params: ptr mbedtls_x509_buf): cint {.importc, cdecl.}
proc mbedtls_x509_get_rsassa_pss_params*(params: ptr mbedtls_x509_buf;
    md_alg: ptr mbedtls_md_type_t; mgf_md: ptr mbedtls_md_type_t;
    salt_len: ptr cint): cint {.importc, cdecl.}
proc mbedtls_x509_get_sig*(p: ptr ptr byte; `end`: ptr byte;
                           sig: ptr mbedtls_x509_buf): cint {.importc, cdecl.}
proc mbedtls_x509_get_sig_alg*(sig_oid: ptr mbedtls_x509_buf;
                               sig_params: ptr mbedtls_x509_buf;
                               md_alg: ptr mbedtls_md_type_t;
                               pk_alg: ptr mbedtls_pk_type_t;
                               sig_opts: ptr pointer): cint {.importc, cdecl.}
proc mbedtls_x509_get_time*(p: ptr ptr byte; `end`: ptr byte;
                            t: ptr mbedtls_x509_time): cint {.importc, cdecl.}
proc mbedtls_x509_get_serial*(p: ptr ptr byte; `end`: ptr byte;
                              serial: ptr mbedtls_x509_buf): cint {.importc,
    cdecl.}
proc mbedtls_x509_get_ext*(p: ptr ptr byte; `end`: ptr byte;
                           ext: ptr mbedtls_x509_buf; tag: cint): cint {.
    importc, cdecl.}
proc mbedtls_x509_sig_alg_gets*(buf: cstring; size: uint;
                                sig_oid: ptr mbedtls_x509_buf;
                                pk_alg: mbedtls_pk_type_t;
                                md_alg: mbedtls_md_type_t; sig_opts: pointer): cint {.
    importc, cdecl.}
proc mbedtls_x509_key_size_helper*(buf: cstring; buf_size: uint; name: cstring): cint {.
    importc, cdecl.}
proc mbedtls_x509_string_to_names*(head: ptr ptr mbedtls_asn1_named_data;
                                   name: cstring): cint {.importc, cdecl.}
proc mbedtls_x509_set_extension*(head: ptr ptr mbedtls_asn1_named_data;
                                 oid: cstring; oid_len: uint; critical: cint;
                                 val: ptr byte; val_len: uint): cint {.
    importc, cdecl.}
proc mbedtls_x509_write_extensions*(p: ptr ptr byte; start: ptr byte;
                                    first: ptr mbedtls_asn1_named_data): cint {.
    importc, cdecl.}
proc mbedtls_x509_write_names*(p: ptr ptr byte; start: ptr byte;
                               first: ptr mbedtls_asn1_named_data): cint {.
    importc, cdecl.}
proc mbedtls_x509_write_sig*(p: ptr ptr byte; start: ptr byte; oid: cstring;
                             oid_len: uint; sig: ptr byte; size: uint): cint {.
    importc, cdecl.}
proc mbedtls_x509_get_ns_cert_type*(p: ptr ptr byte; `end`: ptr byte;
                                    ns_cert_type: ptr byte): cint {.importc,
    cdecl.}
proc mbedtls_x509_get_key_usage*(p: ptr ptr byte; `end`: ptr byte;
                                 key_usage: ptr cuint): cint {.importc, cdecl.}
proc mbedtls_x509_get_subject_alt_name*(p: ptr ptr byte; `end`: ptr byte;
    subject_alt_name: ptr mbedtls_x509_sequence): cint {.importc, cdecl.}
proc mbedtls_x509_info_subject_alt_name*(buf: ptr cstring; size: ptr uint;
    subject_alt_name: ptr mbedtls_x509_sequence; prefix: cstring): cint {.
    importc, cdecl.}
proc mbedtls_x509_info_cert_type*(buf: ptr cstring; size: ptr uint;
                                  ns_cert_type: byte): cint {.importc, cdecl.}
proc mbedtls_x509_info_key_usage*(buf: ptr cstring; size: ptr uint;
                                  key_usage: cuint): cint {.importc, cdecl.}
{.pop.}
