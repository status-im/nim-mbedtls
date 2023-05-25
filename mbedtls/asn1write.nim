{.used.}
import "csources"
import "asn1"
import "bignum"

{.compile: "./mbedtls/csources/library/asn1write.c".}

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}

proc mbedtls_asn1_write_len*(p: ptr ptr byte; start: ptr byte; len: uint): cint {.
    importc, cdecl.}
proc mbedtls_asn1_write_tag*(p: ptr ptr byte; start: ptr byte; tag: byte): cint {.
    importc, cdecl.}
proc mbedtls_asn1_write_raw_buffer*(p: ptr ptr byte; start: ptr byte;
                                    buf: ptr byte; size: uint): cint {.
    importc, cdecl.}
proc mbedtls_asn1_write_mpi*(p: ptr ptr byte; start: ptr byte;
                             X: ptr mbedtls_mpi): cint {.importc, cdecl.}
proc mbedtls_asn1_write_null*(p: ptr ptr byte; start: ptr byte): cint {.
    importc, cdecl.}
proc mbedtls_asn1_write_oid*(p: ptr ptr byte; start: ptr byte; oid: cstring;
                             oid_len: uint): cint {.importc, cdecl.}
proc mbedtls_asn1_write_algorithm_identifier*(p: ptr ptr byte;
    start: ptr byte; oid: cstring; oid_len: uint; par_len: uint): cint {.
    importc, cdecl.}
proc mbedtls_asn1_write_bool*(p: ptr ptr byte; start: ptr byte;
                              boolean: cint): cint {.importc, cdecl.}
proc mbedtls_asn1_write_int*(p: ptr ptr byte; start: ptr byte; val: cint): cint {.
    importc, cdecl.}
proc mbedtls_asn1_write_enum*(p: ptr ptr byte; start: ptr byte; val: cint): cint {.
    importc, cdecl.}
proc mbedtls_asn1_write_tagged_string*(p: ptr ptr byte; start: ptr byte;
                                       tag: cint; text: cstring; text_len: uint): cint {.
    importc, cdecl.}
proc mbedtls_asn1_write_printable_string*(p: ptr ptr byte; start: ptr byte;
    text: cstring; text_len: uint): cint {.importc, cdecl.}
proc mbedtls_asn1_write_utf8_string*(p: ptr ptr byte; start: ptr byte;
                                     text: cstring; text_len: uint): cint {.
    importc, cdecl.}
proc mbedtls_asn1_write_ia5_string*(p: ptr ptr byte; start: ptr byte;
                                    text: cstring; text_len: uint): cint {.
    importc, cdecl.}
proc mbedtls_asn1_write_bitstring*(p: ptr ptr byte; start: ptr byte;
                                   buf: ptr byte; bits: uint): cint {.importc,
    cdecl.}
proc mbedtls_asn1_write_named_bitstring*(p: ptr ptr byte; start: ptr byte;
    buf: ptr byte; bits: uint): cint {.importc, cdecl.}
proc mbedtls_asn1_write_octet_string*(p: ptr ptr byte; start: ptr byte;
                                      buf: ptr byte; size: uint): cint {.
    importc, cdecl.}
proc mbedtls_asn1_store_named_data*(list: ptr ptr mbedtls_asn1_named_data;
                                    oid: cstring; oid_len: uint;
                                    val: ptr byte; val_len: uint): ptr mbedtls_asn1_named_data {.
    importc, cdecl.}
{.pop.}
