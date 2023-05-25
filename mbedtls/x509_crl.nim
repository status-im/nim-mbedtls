{.used.}
import "csources"
import "x509"
import "pk"
import "md"

{.compile: "./mbedtls/csources/library/x509_crl.c".}

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}

type
  mbedtls_x509_crl_entry* {.bycopy.} = object
    raw*: mbedtls_x509_buf
    serial*: mbedtls_x509_buf
    revocation_date*: mbedtls_x509_time
    entry_ext*: mbedtls_x509_buf
    next*: ptr mbedtls_x509_crl_entry

  mbedtls_x509_crl* {.bycopy.} = object
    raw*: mbedtls_x509_buf
    tbs*: mbedtls_x509_buf
    version*: cint
    sig_oid*: mbedtls_x509_buf
    issuer_raw*: mbedtls_x509_buf
    issuer*: mbedtls_x509_name
    this_update*: mbedtls_x509_time
    next_update*: mbedtls_x509_time
    entry*: mbedtls_x509_crl_entry
    crl_ext*: mbedtls_x509_buf
    private_sig_oid2*: mbedtls_x509_buf
    private_sig*: mbedtls_x509_buf
    private_sig_md*: mbedtls_md_type_t
    private_sig_pk*: mbedtls_pk_type_t
    private_sig_opts*: pointer
    next*: ptr mbedtls_x509_crl

proc mbedtls_x509_crl_parse_der*(chain: ptr mbedtls_x509_crl; buf: ptr byte;
                                 buflen: uint): cint {.importc, cdecl.}
proc mbedtls_x509_crl_parse*(chain: ptr mbedtls_x509_crl; buf: ptr byte;
                             buflen: uint): cint {.importc, cdecl.}
proc mbedtls_x509_crl_parse_file*(chain: ptr mbedtls_x509_crl; path: cstring): cint {.
    importc, cdecl.}
proc mbedtls_x509_crl_info*(buf: cstring; size: uint; prefix: cstring;
                            crl: ptr mbedtls_x509_crl): cint {.importc, cdecl.}
proc mbedtls_x509_crl_init*(crl: ptr mbedtls_x509_crl) {.importc, cdecl.}
proc mbedtls_x509_crl_free*(crl: ptr mbedtls_x509_crl) {.importc, cdecl.}
{.pop.}
