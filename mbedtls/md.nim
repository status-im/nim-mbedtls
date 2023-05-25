import "csources"
import "ripemd160"
import "sha1"
import "sha256"
import "sha512"
import "md5"
import "utils"

{.compile: "./mbedtls/csources/library/md.c".}

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}

defineEnum(mbedtls_md_type_t)
defineEnum(mbedtls_md_engine_t)

const
  MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE* = -0x00005080
  MBEDTLS_ERR_MD_BAD_INPUT_DATA* = -0x00005100
  MBEDTLS_ERR_MD_ALLOC_FAILED* = -0x00005180
  MBEDTLS_ERR_MD_FILE_IO_ERROR* = -0x00005200
  MBEDTLS_MD_NONE* = (0).mbedtls_md_type_t
  MBEDTLS_MD_MD5* = (MBEDTLS_MD_NONE + 1).mbedtls_md_type_t
  MBEDTLS_MD_SHA1* = (MBEDTLS_MD_MD5 + 1).mbedtls_md_type_t
  MBEDTLS_MD_SHA224* = (MBEDTLS_MD_SHA1 + 1).mbedtls_md_type_t
  MBEDTLS_MD_SHA256* = (MBEDTLS_MD_SHA224 + 1).mbedtls_md_type_t
  MBEDTLS_MD_SHA384* = (MBEDTLS_MD_SHA256 + 1).mbedtls_md_type_t
  MBEDTLS_MD_SHA512* = (MBEDTLS_MD_SHA384 + 1).mbedtls_md_type_t
  MBEDTLS_MD_RIPEMD160* = (MBEDTLS_MD_SHA512 + 1).mbedtls_md_type_t
  MBEDTLS_MD_MAX_SIZE* = 64
  MBEDTLS_MD_MAX_BLOCK_SIZE* = 128
  MBEDTLS_MD_ENGINE_LEGACY* = (0).mbedtls_md_engine_t
  MBEDTLS_MD_ENGINE_PSA* = (MBEDTLS_MD_ENGINE_LEGACY + 1).mbedtls_md_engine_t
type
  mbedtls_md_info_t* {.incompleteStruct.} = object
  mbedtls_md_context_t* {.bycopy.} = object
    private_md_info*: ptr mbedtls_md_info_t
    private_md_ctx*: pointer
    private_hmac_ctx*: pointer

proc mbedtls_md_info_from_type*(md_type: mbedtls_md_type_t): ptr mbedtls_md_info_t {.
    importc, cdecl.}
proc mbedtls_md_init*(ctx: ptr mbedtls_md_context_t) {.importc, cdecl.}
proc mbedtls_md_free*(ctx: ptr mbedtls_md_context_t) {.importc, cdecl.}
proc mbedtls_md_setup*(ctx: ptr mbedtls_md_context_t;
                       md_info: ptr mbedtls_md_info_t; hmac: cint): cint {.
    importc, cdecl.}
proc mbedtls_md_clone*(dst: ptr mbedtls_md_context_t;
                       src: ptr mbedtls_md_context_t): cint {.importc, cdecl.}
proc mbedtls_md_get_size*(md_info: ptr mbedtls_md_info_t): byte {.importc,
    cdecl.}
proc mbedtls_md_get_type*(md_info: ptr mbedtls_md_info_t): mbedtls_md_type_t {.
    importc, cdecl.}
proc mbedtls_md_starts*(ctx: ptr mbedtls_md_context_t): cint {.importc, cdecl.}
proc mbedtls_md_update*(ctx: ptr mbedtls_md_context_t; input: ptr byte;
                        ilen: uint): cint {.importc, cdecl.}
proc mbedtls_md_finish*(ctx: ptr mbedtls_md_context_t; output: ptr byte): cint {.
    importc, cdecl.}
proc mbedtls_md*(md_info: ptr mbedtls_md_info_t; input: ptr byte; ilen: uint;
                 output: ptr byte): cint {.importc, cdecl.}
proc mbedtls_md_list*(): ptr cint {.importc, cdecl.}
proc mbedtls_md_info_from_string*(md_name: cstring): ptr mbedtls_md_info_t {.
    importc, cdecl.}
proc mbedtls_md_get_name*(md_info: ptr mbedtls_md_info_t): cstring {.importc,
    cdecl.}
proc mbedtls_md_info_from_ctx*(ctx: ptr mbedtls_md_context_t): ptr mbedtls_md_info_t {.
    importc, cdecl.}
proc mbedtls_md_file*(md_info: ptr mbedtls_md_info_t; path: cstring;
                      output: ptr byte): cint {.importc, cdecl.}
proc mbedtls_md_hmac_starts*(ctx: ptr mbedtls_md_context_t; key: ptr byte;
                             keylen: uint): cint {.importc, cdecl.}
proc mbedtls_md_hmac_update*(ctx: ptr mbedtls_md_context_t; input: ptr byte;
                             ilen: uint): cint {.importc, cdecl.}
proc mbedtls_md_hmac_finish*(ctx: ptr mbedtls_md_context_t; output: ptr byte): cint {.
    importc, cdecl.}
proc mbedtls_md_hmac_reset*(ctx: ptr mbedtls_md_context_t): cint {.importc,
    cdecl.}
proc mbedtls_md_hmac*(md_info: ptr mbedtls_md_info_t; key: ptr byte;
                      keylen: uint; input: ptr byte; ilen: uint;
                      output: ptr byte): cint {.importc, cdecl.}
{.pop.}
