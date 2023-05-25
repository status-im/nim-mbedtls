{.used.}
import "csources"
import "psa/crypto"
import "utils"

{.compile: "./mbedtls/csources/library/lms.c".}
{.compile: "./mbedtls/csources/library/lmots.c".}

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}

defineEnum(mbedtls_lms_algorithm_type_t)
defineEnum(mbedtls_lmots_algorithm_type_t)

const
  MBEDTLS_ERR_LMS_BAD_INPUT_DATA* = -0x00000011
  MBEDTLS_ERR_LMS_OUT_OF_PRIVATE_KEYS* = -0x00000013
  MBEDTLS_ERR_LMS_VERIFY_FAILED* = -0x00000015
  MBEDTLS_ERR_LMS_ALLOC_FAILED* = -0x00000017
  MBEDTLS_ERR_LMS_BUFFER_TOO_SMALL* = -0x00000019
  MBEDTLS_LMOTS_N_HASH_LEN_MAX* = (32'u)
  MBEDTLS_LMOTS_P_SIG_DIGIT_COUNT_MAX* = (34'u)
  MBEDTLS_LMOTS_I_KEY_ID_LEN* = (16'u)
  MBEDTLS_LMOTS_Q_LEAF_ID_LEN* = (4'u)
  MBEDTLS_LMOTS_TYPE_LEN* = (4'u)
  MBEDTLS_LMS_TYPE_LEN* = (4)
  MBEDTLS_LMS_M_NODE_BYTES_MAX* = 32
  MBEDTLS_LMS_SHA256_M32_H10* = (0x00000006).mbedtls_lms_algorithm_type_t
  MBEDTLS_LMOTS_SHA256_N32_W8* = (4).mbedtls_lmots_algorithm_type_t
type
  mbedtls_lmots_parameters_t* {.bycopy.} = object
    private_I_key_identifier*: array[(16'u), byte]
    private_q_leaf_identifier*: array[(4'u), byte]
    private_type*: mbedtls_lmots_algorithm_type_t

  mbedtls_lmots_public_t* {.bycopy.} = object
    private_params*: mbedtls_lmots_parameters_t
    private_public_key*: array[(32'u), byte]
    private_have_public_key*: byte

  mbedtls_lms_parameters_t* {.bycopy.} = object
    private_I_key_identifier*: array[(16'u), byte]
    private_otstype*: mbedtls_lmots_algorithm_type_t
    private_type*: mbedtls_lms_algorithm_type_t

  mbedtls_lms_public_t* {.bycopy.} = object
    private_params*: mbedtls_lms_parameters_t
    private_T_1_pub_key*: array[32, byte]
    private_have_public_key*: byte

proc mbedtls_lms_public_init*(ctx: ptr mbedtls_lms_public_t) {.importc, cdecl.}
proc mbedtls_lms_public_free*(ctx: ptr mbedtls_lms_public_t) {.importc, cdecl.}
proc mbedtls_lms_import_public_key*(ctx: ptr mbedtls_lms_public_t;
                                    key: ptr byte; key_size: uint): cint {.
    importc, cdecl.}
proc mbedtls_lms_export_public_key*(ctx: ptr mbedtls_lms_public_t;
                                    key: ptr byte; key_size: uint;
                                    key_len: ptr uint): cint {.importc, cdecl.}
proc mbedtls_lms_verify*(ctx: ptr mbedtls_lms_public_t; msg: ptr byte;
                         msg_size: uint; sig: ptr byte; sig_size: uint): cint {.
    importc, cdecl.}
{.pop.}
