import "md"

{.compile: "./mbedtls/csources/library/hmac_drbg.c".}

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/csources/include".}
{.passc: "-I./mbedtls/csources/library".}

const
  MBEDTLS_ERR_HMAC_DRBG_REQUEST_TOO_BIG* = -0x00000003
  MBEDTLS_ERR_HMAC_DRBG_INPUT_TOO_BIG* = -0x00000005
  MBEDTLS_ERR_HMAC_DRBG_FILE_IO_ERROR* = -0x00000007
  MBEDTLS_ERR_HMAC_DRBG_ENTROPY_SOURCE_FAILED* = -0x00000009
  MBEDTLS_HMAC_DRBG_RESEED_INTERVAL* = 10000
  MBEDTLS_HMAC_DRBG_MAX_INPUT* = 256
  MBEDTLS_HMAC_DRBG_MAX_REQUEST* = 1024
  MBEDTLS_HMAC_DRBG_MAX_SEED_INPUT* = 384
  MBEDTLS_HMAC_DRBG_PR_OFF* = 0
  MBEDTLS_HMAC_DRBG_PR_ON* = 1
type
  mbedtls_hmac_drbg_context* {.bycopy.} = object
    private_md_ctx*: mbedtls_md_context_t
    private_V*: array[64, byte]
    private_reseed_counter*: cint
    private_entropy_len*: uint
    private_prediction_resistance*: cint
    private_reseed_interval*: cint
    private_f_entropy*: proc (a1: pointer; a2: ptr byte; a3: uint): cint {.
        cdecl.}
    private_p_entropy*: pointer

proc mbedtls_hmac_drbg_init*(ctx: ptr mbedtls_hmac_drbg_context) {.importc,
    cdecl.}
proc mbedtls_hmac_drbg_seed*(ctx: ptr mbedtls_hmac_drbg_context;
                             md_info: ptr mbedtls_md_info_t; f_entropy: proc (
    a1: pointer; a2: ptr byte; a3: uint): cint {.cdecl.}; p_entropy: pointer;
                             custom: ptr byte; len: uint): cint {.importc,
    cdecl.}
proc mbedtls_hmac_drbg_seed_buf*(ctx: ptr mbedtls_hmac_drbg_context;
                                 md_info: ptr mbedtls_md_info_t;
                                 data: ptr byte; data_len: uint): cint {.
    importc, cdecl.}
proc mbedtls_hmac_drbg_set_prediction_resistance*(
    ctx: ptr mbedtls_hmac_drbg_context; resistance: cint) {.importc, cdecl.}
proc mbedtls_hmac_drbg_set_entropy_len*(ctx: ptr mbedtls_hmac_drbg_context;
                                        len: uint) {.importc, cdecl.}
proc mbedtls_hmac_drbg_set_reseed_interval*(ctx: ptr mbedtls_hmac_drbg_context;
    interval: cint) {.importc, cdecl.}
proc mbedtls_hmac_drbg_update*(ctx: ptr mbedtls_hmac_drbg_context;
                               additional: ptr byte; add_len: uint): cint {.
    importc, cdecl.}
proc mbedtls_hmac_drbg_reseed*(ctx: ptr mbedtls_hmac_drbg_context;
                               additional: ptr byte; len: uint): cint {.
    importc, cdecl.}
proc mbedtls_hmac_drbg_random_with_add*(p_rng: pointer; output: ptr byte;
                                        output_len: uint;
                                        additional: ptr byte; add_len: uint): cint {.
    importc, cdecl.}
proc mbedtls_hmac_drbg_random*(p_rng: pointer; output: ptr byte; out_len: uint): cint {.
    importc, cdecl.}
proc mbedtls_hmac_drbg_free*(ctx: ptr mbedtls_hmac_drbg_context) {.importc,
    cdecl.}
proc mbedtls_hmac_drbg_write_seed_file*(ctx: ptr mbedtls_hmac_drbg_context;
                                        path: cstring): cint {.importc, cdecl.}
proc mbedtls_hmac_drbg_update_seed_file*(ctx: ptr mbedtls_hmac_drbg_context;
    path: cstring): cint {.importc, cdecl.}
proc mbedtls_hmac_drbg_self_test*(verbose: cint): cint {.importc, cdecl.}
{.pop.}
