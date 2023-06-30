{.used.}
import "csources"
import "x509"
import "x509_crl"
import "asn1"
import "bignum"
import "md"
import "pk"

{.compile: "./mbedtls/csources/library/x509_crt.c".}
{.compile: "./mbedtls/csources/library/x509write_crt.c".}

# const 'MBEDTLS_X509_CRT_ERROR_INFO_LIST' has unsupported value 'X509_CRT_ERROR_INFO(MBEDTLS_X509_BADCERT_EXPIRED, "MBEDTLS_X509_BADCERT_EXPIRED", "The certificate validity has expired") X509_CRT_ERROR_INFO(MBEDTLS_X509_BADCERT_REVOKED, "MBEDTLS_X509_BADCERT_REVOKED", "The certificate has been revoked (is on a CRL)") X509_CRT_ERROR_INFO(MBEDTLS_X509_BADCERT_CN_MISMATCH, "MBEDTLS_X509_BADCERT_CN_MISMATCH", "The certificate Common Name (CN) does not match with the expected CN") X509_CRT_ERROR_INFO(MBEDTLS_X509_BADCERT_NOT_TRUSTED, "MBEDTLS_X509_BADCERT_NOT_TRUSTED", "The certificate is not correctly signed by the trusted CA") X509_CRT_ERROR_INFO(MBEDTLS_X509_BADCRL_NOT_TRUSTED, "MBEDTLS_X509_BADCRL_NOT_TRUSTED", "The CRL is not correctly signed by the trusted CA") X509_CRT_ERROR_INFO(MBEDTLS_X509_BADCRL_EXPIRED, "MBEDTLS_X509_BADCRL_EXPIRED", "The CRL is expired") X509_CRT_ERROR_INFO(MBEDTLS_X509_BADCERT_MISSING, "MBEDTLS_X509_BADCERT_MISSING", "Certificate was missing") X509_CRT_ERROR_INFO(MBEDTLS_X509_BADCERT_SKIP_VERIFY, "MBEDTLS_X509_BADCERT_SKIP_VERIFY", "Certificate verification was skipped") X509_CRT_ERROR_INFO(MBEDTLS_X509_BADCERT_OTHER, "MBEDTLS_X509_BADCERT_OTHER", "Other reason (can be used by verify callback)") X509_CRT_ERROR_INFO(MBEDTLS_X509_BADCERT_FUTURE, "MBEDTLS_X509_BADCERT_FUTURE", "The certificate validity starts in the future") X509_CRT_ERROR_INFO(MBEDTLS_X509_BADCRL_FUTURE, "MBEDTLS_X509_BADCRL_FUTURE", "The CRL is from the future") X509_CRT_ERROR_INFO(MBEDTLS_X509_BADCERT_KEY_USAGE, "MBEDTLS_X509_BADCERT_KEY_USAGE", "Usage does not match the keyUsage extension") X509_CRT_ERROR_INFO(MBEDTLS_X509_BADCERT_EXT_KEY_USAGE, "MBEDTLS_X509_BADCERT_EXT_KEY_USAGE", "Usage does not match the extendedKeyUsage extension") X509_CRT_ERROR_INFO(MBEDTLS_X509_BADCERT_NS_CERT_TYPE, "MBEDTLS_X509_BADCERT_NS_CERT_TYPE", "Usage does not match the nsCertType extension") X509_CRT_ERROR_INFO(MBEDTLS_X509_BADCERT_BAD_MD, "MBEDTLS_X509_BADCERT_BAD_MD", "The certificate is signed with an unacceptable hash.") X509_CRT_ERROR_INFO(MBEDTLS_X509_BADCERT_BAD_PK, "MBEDTLS_X509_BADCERT_BAD_PK", "The certificate is signed with an unacceptable PK alg (eg RSA vs ECDSA).") X509_CRT_ERROR_INFO(MBEDTLS_X509_BADCERT_BAD_KEY, "MBEDTLS_X509_BADCERT_BAD_KEY", "The certificate is signed with an unacceptable key (eg bad curve, RSA too short).") X509_CRT_ERROR_INFO(MBEDTLS_X509_BADCRL_BAD_MD, "MBEDTLS_X509_BADCRL_BAD_MD", "The CRL is signed with an unacceptable hash.") X509_CRT_ERROR_INFO(MBEDTLS_X509_BADCRL_BAD_PK, "MBEDTLS_X509_BADCRL_BAD_PK", "The CRL is signed with an unacceptable PK alg (eg RSA vs ECDSA).") X509_CRT_ERROR_INFO(MBEDTLS_X509_BADCRL_BAD_KEY, "MBEDTLS_X509_BADCRL_BAD_KEY", "The CRL is signed with an unacceptable key (eg bad curve, RSA too short).")'
# const 'MBEDTLS_X509_MAX_VERIFY_CHAIN_SIZE' has unsupported value '(MBEDTLS_X509_MAX_INTERMEDIATE_CA + 2)'
# proc 'mbedtls_x509_crt_has_ext_type' skipped - static inline procs cannot work with '--noHeader | -H'

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}

const
  MBEDTLS_X509_CRT_VERSION_1* = 0
  MBEDTLS_X509_CRT_VERSION_2* = 1
  MBEDTLS_X509_CRT_VERSION_3* = 2
  MBEDTLS_X509_RFC5280_MAX_SERIAL_LEN* = 20
  MBEDTLS_X509_RFC5280_UTC_TIME_LEN* = 15
  MBEDTLS_X509_MAX_FILE_PATH_LEN* = 512
type
  mbedtls_x509_crt* {.bycopy.} = object
    private_own_buffer*: cint
    raw*: mbedtls_x509_buf
    tbs*: mbedtls_x509_buf
    version*: cint
    serial*: mbedtls_x509_buf
    sig_oid*: mbedtls_x509_buf
    issuer_raw*: mbedtls_x509_buf
    subject_raw*: mbedtls_x509_buf
    issuer*: mbedtls_x509_name
    subject*: mbedtls_x509_name
    valid_from*: mbedtls_x509_time
    valid_to*: mbedtls_x509_time
    pk_raw*: mbedtls_x509_buf
    pk*: mbedtls_pk_context
    issuer_id*: mbedtls_x509_buf
    subject_id*: mbedtls_x509_buf
    v3_ext*: mbedtls_x509_buf
    subject_alt_names*: mbedtls_x509_sequence
    certificate_policies*: mbedtls_x509_sequence
    private_ext_types*: cint
    private_ca_istrue*: cint
    private_max_pathlen*: cint
    private_key_usage*: cuint
    ext_key_usage*: mbedtls_x509_sequence
    private_ns_cert_type*: byte
    private_sig*: mbedtls_x509_buf
    private_sig_md*: mbedtls_md_type_t
    private_sig_pk*: mbedtls_pk_type_t
    private_sig_opts*: pointer
    next*: ptr mbedtls_x509_crt

  mbedtls_x509_crt_profile* {.bycopy.} = object
    allowed_mds*: uint32
    allowed_pks*: uint32
    allowed_curves*: uint32
    rsa_min_bitlen*: uint32

  mbedtls_x509write_cert* {.bycopy.} = object
    private_version*: cint
    private_serial*: array[20, byte]
    private_serial_len*: uint
    private_subject_key*: ptr mbedtls_pk_context
    private_issuer_key*: ptr mbedtls_pk_context
    private_subject*: ptr mbedtls_asn1_named_data
    private_issuer*: ptr mbedtls_asn1_named_data
    private_md_alg*: mbedtls_md_type_t
    private_not_before*: array[15 + typeof(15)(1), cchar]
    private_not_after*: array[15 + typeof(15)(1), cchar]
    private_extensions*: ptr mbedtls_asn1_named_data

  mbedtls_x509_crt_verify_chain_item* {.bycopy.} = object
    private_crt*: ptr mbedtls_x509_crt
    private_flags*: uint32

  mbedtls_x509_crt_verify_chain* {.bycopy.} = object
    private_items*: array[(8 + typeof(8)(2)), mbedtls_x509_crt_verify_chain_item]
    private_len*: cuint

  mbedtls_x509_crt_restart_ctx* = object
  mbedtls_x509_crt_ext_cb_t* = proc (p_ctx: pointer; crt: ptr mbedtls_x509_crt;
                                     oid: ptr mbedtls_x509_buf; critical: cint;
                                     p: ptr byte; `end`: ptr byte): cint {.
      cdecl.}
  mbedtls_x509_crt_ca_cb_t* = proc (p_ctx: pointer; child: ptr mbedtls_x509_crt;
                                    candidate_cas: ptr ptr mbedtls_x509_crt): cint {.
      cdecl.}
var
  mbedtls_x509_crt_profile_default* {.importc.}: mbedtls_x509_crt_profile
  mbedtls_x509_crt_profile_next* {.importc.}: mbedtls_x509_crt_profile
  mbedtls_x509_crt_profile_suiteb* {.importc.}: mbedtls_x509_crt_profile
  mbedtls_x509_crt_profile_none* {.importc.}: mbedtls_x509_crt_profile
proc mbedtls_x509_crt_parse_der*(chain: ptr mbedtls_x509_crt; buf: ptr byte;
                                 buflen: uint): cint {.importc, cdecl.}
proc mbedtls_x509_crt_parse_der_with_ext_cb*(chain: ptr mbedtls_x509_crt;
    buf: ptr byte; buflen: uint; make_copy: cint;
    cb: mbedtls_x509_crt_ext_cb_t; p_ctx: pointer): cint {.importc, cdecl.}
proc mbedtls_x509_crt_parse_der_nocopy*(chain: ptr mbedtls_x509_crt;
                                        buf: ptr byte; buflen: uint): cint {.
    importc, cdecl.}
proc mbedtls_x509_crt_parse*(chain: ptr mbedtls_x509_crt; buf: ptr byte;
                             buflen: uint): cint {.importc, cdecl.}
proc mbedtls_x509_crt_parse_file*(chain: ptr mbedtls_x509_crt; path: cstring): cint {.
    importc, cdecl.}
proc mbedtls_x509_crt_parse_path*(chain: ptr mbedtls_x509_crt; path: cstring): cint {.
    importc, cdecl.}
proc mbedtls_x509_crt_info*(buf: cstring; size: uint; prefix: cstring;
                            crt: ptr mbedtls_x509_crt): cint {.importc, cdecl.}
proc mbedtls_x509_crt_verify_info*(buf: cstring; size: uint; prefix: cstring;
                                   flags: uint32): cint {.importc, cdecl.}
proc mbedtls_x509_crt_verify*(crt: ptr mbedtls_x509_crt;
                              trust_ca: ptr mbedtls_x509_crt;
                              ca_crl: ptr mbedtls_x509_crl; cn: cstring;
                              flags: ptr uint32; f_vrfy: proc (a1: pointer;
    a2: ptr mbedtls_x509_crt; a3: cint; a4: ptr uint32): cint {.cdecl.};
                              p_vrfy: pointer): cint {.importc, cdecl.}
proc mbedtls_x509_crt_verify_with_profile*(crt: ptr mbedtls_x509_crt;
    trust_ca: ptr mbedtls_x509_crt; ca_crl: ptr mbedtls_x509_crl;
    profile: ptr mbedtls_x509_crt_profile; cn: cstring; flags: ptr uint32;
    f_vrfy: proc (a1: pointer; a2: ptr mbedtls_x509_crt; a3: cint;
                  a4: ptr uint32): cint {.cdecl.}; p_vrfy: pointer): cint {.
    importc, cdecl.}
proc mbedtls_x509_crt_verify_restartable*(crt: ptr mbedtls_x509_crt;
    trust_ca: ptr mbedtls_x509_crt; ca_crl: ptr mbedtls_x509_crl;
    profile: ptr mbedtls_x509_crt_profile; cn: cstring; flags: ptr uint32;
    f_vrfy: proc (a1: pointer; a2: ptr mbedtls_x509_crt; a3: cint;
                  a4: ptr uint32): cint {.cdecl.}; p_vrfy: pointer;
    rs_ctx: ptr mbedtls_x509_crt_restart_ctx): cint {.importc, cdecl.}
proc mbedtls_x509_crt_check_key_usage*(crt: ptr mbedtls_x509_crt; usage: cuint): cint {.
    importc, cdecl.}
proc mbedtls_x509_crt_check_extended_key_usage*(crt: ptr mbedtls_x509_crt;
    usage_oid: cstring; usage_len: uint): cint {.importc, cdecl.}
proc mbedtls_x509_crt_is_revoked*(crt: ptr mbedtls_x509_crt;
                                  crl: ptr mbedtls_x509_crl): cint {.importc,
    cdecl.}
proc mbedtls_x509_crt_init*(crt: ptr mbedtls_x509_crt) {.importc, cdecl.}
proc mbedtls_x509_crt_free*(crt: ptr mbedtls_x509_crt) {.importc, cdecl.}
proc mbedtls_x509write_crt_init*(ctx: ptr mbedtls_x509write_cert) {.importc,
    cdecl.}
proc mbedtls_x509write_crt_set_version*(ctx: ptr mbedtls_x509write_cert;
                                        version: cint) {.importc, cdecl.}
proc mbedtls_x509write_crt_set_serial*(ctx: ptr mbedtls_x509write_cert;
                                       serial: ptr mbedtls_mpi): cint {.importc,
    cdecl.}
proc mbedtls_x509write_crt_set_serial_raw*(ctx: ptr mbedtls_x509write_cert;
    serial: ptr byte; serial_len: uint): cint {.importc, cdecl.}
proc mbedtls_x509write_crt_set_validity*(ctx: ptr mbedtls_x509write_cert;
    not_before: cstring; not_after: cstring): cint {.importc, cdecl.}
proc mbedtls_x509write_crt_set_issuer_name*(ctx: ptr mbedtls_x509write_cert;
    issuer_name: cstring): cint {.importc, cdecl.}
proc mbedtls_x509write_crt_set_subject_name*(ctx: ptr mbedtls_x509write_cert;
    subject_name: cstring): cint {.importc, cdecl.}
proc mbedtls_x509write_crt_set_subject_key*(ctx: ptr mbedtls_x509write_cert;
    key: ptr mbedtls_pk_context) {.importc, cdecl.}
proc mbedtls_x509write_crt_set_issuer_key*(ctx: ptr mbedtls_x509write_cert;
    key: ptr mbedtls_pk_context) {.importc, cdecl.}
proc mbedtls_x509write_crt_set_md_alg*(ctx: ptr mbedtls_x509write_cert;
                                       md_alg: mbedtls_md_type_t) {.importc,
    cdecl.}
proc mbedtls_x509write_crt_set_extension*(ctx: ptr mbedtls_x509write_cert;
    oid: cstring; oid_len: uint; critical: cint; val: ptr byte; val_len: uint): cint {.
    importc, cdecl.}
proc mbedtls_x509write_crt_set_basic_constraints*(
    ctx: ptr mbedtls_x509write_cert; is_ca: cint; max_pathlen: cint): cint {.
    importc, cdecl.}
proc mbedtls_x509write_crt_set_subject_key_identifier*(
    ctx: ptr mbedtls_x509write_cert): cint {.importc, cdecl.}
proc mbedtls_x509write_crt_set_authority_key_identifier*(
    ctx: ptr mbedtls_x509write_cert): cint {.importc, cdecl.}
proc mbedtls_x509write_crt_set_key_usage*(ctx: ptr mbedtls_x509write_cert;
    key_usage: cuint): cint {.importc, cdecl.}
proc mbedtls_x509write_crt_set_ext_key_usage*(ctx: ptr mbedtls_x509write_cert;
    exts: ptr mbedtls_asn1_sequence): cint {.importc, cdecl.}
proc mbedtls_x509write_crt_set_ns_cert_type*(ctx: ptr mbedtls_x509write_cert;
    ns_cert_type: byte): cint {.importc, cdecl.}
proc mbedtls_x509write_crt_free*(ctx: ptr mbedtls_x509write_cert) {.importc,
    cdecl.}
proc mbedtls_x509write_crt_der*(ctx: ptr mbedtls_x509write_cert;
                                buf: ptr byte; size: uint; f_rng: proc (
    a1: pointer; a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer): cint {.
    importc, cdecl.}
proc mbedtls_x509write_crt_pem*(ctx: ptr mbedtls_x509write_cert;
                                buf: ptr byte; size: uint; f_rng: proc (
    a1: pointer; a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer): cint {.
    importc, cdecl.}
{.pop.}

import "error"
import "ctr_drbg"

template mb_x509write_crt_init*(ctx: mbedtls_x509write_cert) =
  mbedtls_x509write_crt_init(addr ctx)
template mb_x509write_crt_set_md_alg*(ctx: mbedtls_x509write_cert, md_alg: mbedtls_md_type_t) =
  mbedtls_x509write_crt_set_md_alg(addr ctx, md_alg)
template mb_x509write_crt_set_subject_key*(ctx: mbedtls_x509write_cert, key: mbedtls_pk_context) =
  mbedtls_x509write_crt_set_subject_key(addr ctx, key)
template mb_x509write_crt_set_issuer_key*(ctx: mbedtls_x509write_cert, key: mbedtls_pk_context) =
  mbedtls_x509write_crt_set_issuer_key(addr ctx, key)
template mb_x509write_crt_set_subject_name*(ctx: mbedtls_x509write_cert, name: string) =
  let ret = mbedtls_x509write_crt_set_subject_name(addr ctx, name.cstring)
  if ret != 0:
    raise newException(MbedTLSError, $(ret.mbedtls_high_level_strerr()))
template mb_x509write_crt_set_issuer_name*(ctx: mbedtls_x509write_cert, name: string) =
  let ret = mbedtls_x509write_crt_set_issuer_name(addr ctx, name.cstring)
  if ret != 0:
    raise newException(MbedTLSError, $(ret.mbedtls_high_level_strerr()))
template mb_x509write_crt_set_validity*(ctx: mbedtls_x509write_cert,
                                    not_before: string, not_after: string) =
  let ret = mbedtls_x509write_crt_set_validity(addr ctx, not_before.cstring, not_after.cstring)
  if ret != 0:
    raise newException(MbedTLSError, $(ret.mbedtls_high_level_strerr()))
template mb_x509write_crt_set_basic_constraints*(ctx: mbedtls_x509write_cert,
                                        is_ca: int; max_pathlen: int) =
  let ret = mbedtls_x509write_crt_set_basic_constraints(addr ctx, is_ca.cint, max_pathlen.cint)
  if ret != 0:
    raise newException(MbedTLSError, $(ret.mbedtls_high_level_strerr()))
template mb_x509write_crt_set_subject_key_identifier*(ctx: mbedtls_x509write_cert) =
  let ret = mbedtls_x509write_crt_set_subject_key_identifier(addr ctx)
  if ret != 0:
    raise newException(MbedTLSError, $(ret.mbedtls_high_level_strerr()))
template mb_x509write_crt_set_authority_key_identifier*(ctx: mbedtls_x509write_cert) =
  let ret = mbedtls_x509write_crt_set_authority_key_identifier(addr ctx)
  if ret != 0:
    raise newException(MbedTLSError, $(ret.mbedtls_high_level_strerr()))
template mb_x509write_crt_set_serial*(ctx: mbedtls_x509write_cert, serial: mbedtls_mpi) =
  let ret = mbedtls_x509write_crt_set_serial(addr ctx, addr serial)
  if ret != 0:
    raise newException(MbedTLSError, $(ret.mbedtls_high_level_strerr()))
template mb_x509write_crt_pem*(ctx: mbedtls_x509write_cert, size: uint,
                            f_rng: proc (a1: pointer; a2: ptr byte; a3: uint): cint,
                            p_rng: mbedtls_ctr_drbg_context): string =
  var buf = newString(size)
  let ret = mbedtls_x509write_crt_pem(addr ctx, cast[ptr byte](buf.cstring), size,
                                      f_rng, cast[pointer](addr p_rng))
  if ret != 0:
    raise newException(MbedTLSError, $(ret.mbedtls_high_level_strerr()))
  return buf
template mb_x509_crt_parse*(chain: mbedtls_x509_crt, buf: string) =
  let
    bufcstring = buf.cstring
    ret = mbedtls_x509_crt_parse(addr chain,
                                 cast[ptr byte](bufcstring),
                                 bucstring.len().uint + 1)
  if ret != 0:
    raise newException(MbedTLSError, $(ret.mbedtls_high_level_strerr()))
