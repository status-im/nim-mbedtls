{.used.}
import "csources"
import "aes"
import "entropy"

{.compile: "./mbedtls/csources/library/ctr_drbg.c".}

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}

const
  MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED* = -0x00000034
  MBEDTLS_ERR_CTR_DRBG_REQUEST_TOO_BIG* = -0x00000036
  MBEDTLS_ERR_CTR_DRBG_INPUT_TOO_BIG* = -0x00000038
  MBEDTLS_ERR_CTR_DRBG_FILE_IO_ERROR* = -0x0000003A
  MBEDTLS_CTR_DRBG_BLOCKSIZE* = 16
  MBEDTLS_CTR_DRBG_KEYSIZE* = 32
  MBEDTLS_CTR_DRBG_KEYBITS* = (
    MBEDTLS_CTR_DRBG_KEYSIZE * typeof(MBEDTLS_CTR_DRBG_KEYSIZE)(8))
  MBEDTLS_CTR_DRBG_SEEDLEN* = (MBEDTLS_CTR_DRBG_KEYSIZE +
      typeof(MBEDTLS_CTR_DRBG_KEYSIZE)(MBEDTLS_CTR_DRBG_BLOCKSIZE))
  MBEDTLS_CTR_DRBG_ENTROPY_LEN* = 48
  MBEDTLS_CTR_DRBG_RESEED_INTERVAL* = 10000
  MBEDTLS_CTR_DRBG_MAX_INPUT* = 256
  MBEDTLS_CTR_DRBG_MAX_REQUEST* = 1024
  MBEDTLS_CTR_DRBG_MAX_SEED_INPUT* = 384
  MBEDTLS_CTR_DRBG_PR_OFF* = 0
  MBEDTLS_CTR_DRBG_PR_ON* = 1
  MBEDTLS_CTR_DRBG_ENTROPY_NONCE_LEN* = 0
type
  mbedtls_ctr_drbg_context* {.bycopy.} = object
    private_counter*: array[16, byte]
    private_reseed_counter*: cint
    private_prediction_resistance*: cint
    private_entropy_len*: uint
    private_reseed_interval*: cint
    private_aes_ctx*: mbedtls_aes_context
    private_f_entropy*: proc (a1: pointer; a2: ptr byte; a3: uint): cint {.
        cdecl.}
    private_p_entropy*: pointer

proc mbedtls_ctr_drbg_init*(ctx: ptr mbedtls_ctr_drbg_context) {.importc, cdecl.}
proc mbedtls_ctr_drbg_seed*(ctx: ptr mbedtls_ctr_drbg_context; f_entropy: proc (
    a1: pointer; a2: ptr byte; a3: uint): cint {.cdecl.}; p_entropy: pointer;
                            custom: ptr byte; len: uint): cint {.importc,
    cdecl.}
proc mbedtls_ctr_drbg_free*(ctx: ptr mbedtls_ctr_drbg_context) {.importc, cdecl.}
proc mbedtls_ctr_drbg_set_prediction_resistance*(
    ctx: ptr mbedtls_ctr_drbg_context; resistance: cint) {.importc, cdecl.}
proc mbedtls_ctr_drbg_set_entropy_len*(ctx: ptr mbedtls_ctr_drbg_context;
                                       len: uint) {.importc, cdecl.}
proc mbedtls_ctr_drbg_set_nonce_len*(ctx: ptr mbedtls_ctr_drbg_context;
                                     len: uint): cint {.importc, cdecl.}
proc mbedtls_ctr_drbg_set_reseed_interval*(ctx: ptr mbedtls_ctr_drbg_context;
    interval: cint) {.importc, cdecl.}
proc mbedtls_ctr_drbg_reseed*(ctx: ptr mbedtls_ctr_drbg_context;
                              additional: ptr byte; len: uint): cint {.
    importc, cdecl.}
proc mbedtls_ctr_drbg_update*(ctx: ptr mbedtls_ctr_drbg_context;
                              additional: ptr byte; add_len: uint): cint {.
    importc, cdecl.}
proc mbedtls_ctr_drbg_random_with_add*(p_rng: pointer; output: ptr byte;
                                       output_len: uint; additional: ptr byte;
                                       add_len: uint): cint {.importc, cdecl.}
proc mbedtls_ctr_drbg_random*(p_rng: pointer; output: ptr byte;
                              output_len: uint): cint {.importc, cdecl.}
proc mbedtls_ctr_drbg_write_seed_file*(ctx: ptr mbedtls_ctr_drbg_context;
                                       path: cstring): cint {.importc, cdecl.}
proc mbedtls_ctr_drbg_update_seed_file*(ctx: ptr mbedtls_ctr_drbg_context;
                                        path: cstring): cint {.importc, cdecl.}
proc mbedtls_ctr_drbg_self_test*(verbose: cint): cint {.importc, cdecl.}
{.pop.}
