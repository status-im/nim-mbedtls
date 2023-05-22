import "bignum"

{.compile: "./mbedtls/csources/library/asn1parse.c".}

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/csources/include".}
{.passc: "-I./mbedtls/csources/library".}

const
  MBEDTLS_ERR_ASN1_OUT_OF_DATA* = -0x00000060
  MBEDTLS_ERR_ASN1_UNEXPECTED_TAG* = -0x00000062
  MBEDTLS_ERR_ASN1_INVALID_LENGTH* = -0x00000064
  MBEDTLS_ERR_ASN1_LENGTH_MISMATCH* = -0x00000066
  MBEDTLS_ERR_ASN1_INVALID_DATA* = -0x00000068
  MBEDTLS_ERR_ASN1_ALLOC_FAILED* = -0x0000006A
  MBEDTLS_ERR_ASN1_BUF_TOO_SMALL* = -0x0000006C
  MBEDTLS_ASN1_BOOLEAN* = 0x00000001
  MBEDTLS_ASN1_INTEGER* = 0x00000002
  MBEDTLS_ASN1_BIT_STRING* = 0x00000003
  MBEDTLS_ASN1_OCTET_STRING* = 0x00000004
  MBEDTLS_ASN1_NULL* = 0x00000005
  MBEDTLS_ASN1_OID* = 0x00000006
  MBEDTLS_ASN1_ENUMERATED* = 0x0000000A
  MBEDTLS_ASN1_UTF8_STRING* = 0x0000000C
  MBEDTLS_ASN1_SEQUENCE* = 0x00000010
  MBEDTLS_ASN1_SET* = 0x00000011
  MBEDTLS_ASN1_PRINTABLE_STRING* = 0x00000013
  MBEDTLS_ASN1_T61_STRING* = 0x00000014
  MBEDTLS_ASN1_IA5_STRING* = 0x00000016
  MBEDTLS_ASN1_UTC_TIME* = 0x00000017
  MBEDTLS_ASN1_GENERALIZED_TIME* = 0x00000018
  MBEDTLS_ASN1_UNIVERSAL_STRING* = 0x0000001C
  MBEDTLS_ASN1_BMP_STRING* = 0x0000001E
  MBEDTLS_ASN1_PRIMITIVE* = 0x00000000
  MBEDTLS_ASN1_CONSTRUCTED* = 0x00000020
  MBEDTLS_ASN1_CONTEXT_SPECIFIC* = 0x00000080
  MBEDTLS_ASN1_TAG_CLASS_MASK* = 0x000000C0
  MBEDTLS_ASN1_TAG_PC_MASK* = 0x00000020
  MBEDTLS_ASN1_TAG_VALUE_MASK* = 0x0000001F
type
  mbedtls_asn1_buf* {.bycopy.} = object
    tag*: cint
    len*: uint
    p*: ptr byte

  mbedtls_asn1_bitstring* {.bycopy.} = object
    len*: uint
    unused_bits*: byte
    p*: ptr byte

  mbedtls_asn1_sequence* {.bycopy.} = object
    buf*: mbedtls_asn1_buf
    next*: ptr mbedtls_asn1_sequence

  mbedtls_asn1_named_data* {.bycopy.} = object
    oid*: mbedtls_asn1_buf
    val*: mbedtls_asn1_buf
    next*: ptr mbedtls_asn1_named_data
    private_next_merged*: byte

proc mbedtls_asn1_get_len*(p: ptr ptr byte; `end`: ptr byte; len: ptr uint): cint {.
    importc, cdecl.}
proc mbedtls_asn1_get_tag*(p: ptr ptr byte; `end`: ptr byte; len: ptr uint;
                           tag: cint): cint {.importc, cdecl.}
proc mbedtls_asn1_get_bool*(p: ptr ptr byte; `end`: ptr byte; val: ptr cint): cint {.
    importc, cdecl.}
proc mbedtls_asn1_get_int*(p: ptr ptr byte; `end`: ptr byte; val: ptr cint): cint {.
    importc, cdecl.}
proc mbedtls_asn1_get_enum*(p: ptr ptr byte; `end`: ptr byte; val: ptr cint): cint {.
    importc, cdecl.}
proc mbedtls_asn1_get_bitstring*(p: ptr ptr byte; `end`: ptr byte;
                                 bs: ptr mbedtls_asn1_bitstring): cint {.
    importc, cdecl.}
proc mbedtls_asn1_get_bitstring_null*(p: ptr ptr byte; `end`: ptr byte;
                                      len: ptr uint): cint {.importc, cdecl.}
proc mbedtls_asn1_get_sequence_of*(p: ptr ptr byte; `end`: ptr byte;
                                   cur: ptr mbedtls_asn1_sequence; tag: cint): cint {.
    importc, cdecl.}
proc mbedtls_asn1_sequence_free*(seq: ptr mbedtls_asn1_sequence) {.importc,
    cdecl.}
proc mbedtls_asn1_traverse_sequence_of*(p: ptr ptr byte; `end`: ptr byte;
                                        tag_must_mask: byte;
                                        tag_must_val: byte;
                                        tag_may_mask: byte;
                                        tag_may_val: byte; cb: proc (
    ctx: pointer; tag: cint; start: ptr byte; len: uint): cint {.cdecl.};
                                        ctx: pointer): cint {.importc, cdecl.}
proc mbedtls_asn1_get_mpi*(p: ptr ptr byte; `end`: ptr byte;
                           X: ptr mbedtls_mpi): cint {.importc, cdecl.}
proc mbedtls_asn1_get_alg*(p: ptr ptr byte; `end`: ptr byte;
                           alg: ptr mbedtls_asn1_buf;
                           params: ptr mbedtls_asn1_buf): cint {.importc, cdecl.}
proc mbedtls_asn1_get_alg_null*(p: ptr ptr byte; `end`: ptr byte;
                                alg: ptr mbedtls_asn1_buf): cint {.importc,
    cdecl.}
proc mbedtls_asn1_find_named_data*(list: ptr mbedtls_asn1_named_data;
                                   oid: cstring; len: uint): ptr mbedtls_asn1_named_data {.
    importc, cdecl.}
proc mbedtls_asn1_free_named_data*(entry: ptr mbedtls_asn1_named_data) {.
    importc, cdecl.}
proc mbedtls_asn1_free_named_data_list*(head: ptr ptr mbedtls_asn1_named_data) {.
    importc, cdecl.}
proc mbedtls_asn1_free_named_data_list_shallow*(
    name: ptr mbedtls_asn1_named_data) {.importc, cdecl.}
{.pop.}
