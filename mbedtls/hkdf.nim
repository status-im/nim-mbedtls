import "csources"
import "md"

{.compile: "./mbedtls/csources/library/hkdf.c".}

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}

const
  MBEDTLS_ERR_HKDF_BAD_INPUT_DATA* = -0x00005F80
proc mbedtls_hkdf*(md: ptr mbedtls_md_info_t; salt: ptr byte; salt_len: uint;
                   ikm: ptr byte; ikm_len: uint; info: ptr byte;
                   info_len: uint; okm: ptr byte; okm_len: uint): cint {.
    importc, cdecl.}
proc mbedtls_hkdf_extract*(md: ptr mbedtls_md_info_t; salt: ptr byte;
                           salt_len: uint; ikm: ptr byte; ikm_len: uint;
                           prk: ptr byte): cint {.importc, cdecl.}
proc mbedtls_hkdf_expand*(md: ptr mbedtls_md_info_t; prk: ptr byte;
                          prk_len: uint; info: ptr byte; info_len: uint;
                          okm: ptr byte; okm_len: uint): cint {.importc, cdecl.}
{.pop.}
