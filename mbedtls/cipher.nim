import "csources"
import "aes"
import "aria"
import "camellia"
import "chachapoly"
import "des"
import "constant_time"
import "utils"

{.compile: "./mbedtls/csources/library/ccm.c".}
{.compile: "./mbedtls/csources/library/gcm.c".}
{.compile: "./mbedtls/csources/library/nist_kw.c".}
{.compile: "./mbedtls/csources/library/cipher_wrap.c".}
{.compile: "./mbedtls/csources/library/cipher.c".}

# proc 'mbedtls_cipher_info_get_type' skipped - static inline procs cannot work with '--noHeader | -H'
# proc 'mbedtls_cipher_info_get_mode' skipped - static inline procs cannot work with '--noHeader | -H'
# proc 'mbedtls_cipher_info_get_key_bitlen' skipped - static inline procs cannot work with '--noHeader | -H'
# proc 'mbedtls_cipher_info_get_name' skipped - static inline procs cannot work with '--noHeader | -H'
# proc 'mbedtls_cipher_info_get_iv_size' skipped - static inline procs cannot work with '--noHeader | -H'
# proc 'mbedtls_cipher_info_get_block_size' skipped - static inline procs cannot work with '--noHeader | -H'
# proc 'mbedtls_cipher_info_has_variable_key_bitlen' skipped - static inline procs cannot work with '--noHeader | -H'
# proc 'mbedtls_cipher_info_has_variable_iv_size' skipped - static inline procs cannot work with '--noHeader | -H'
# proc 'mbedtls_cipher_get_block_size' skipped - static inline procs cannot work with '--noHeader | -H'
# proc 'mbedtls_cipher_get_cipher_mode' skipped - static inline procs cannot work with '--noHeader | -H'
# proc 'mbedtls_cipher_get_iv_size' skipped - static inline procs cannot work with '--noHeader | -H'
# proc 'mbedtls_cipher_get_type' skipped - static inline procs cannot work with '--noHeader | -H'
# proc 'mbedtls_cipher_get_name' skipped - static inline procs cannot work with '--noHeader | -H'
# proc 'mbedtls_cipher_get_key_bitlen' skipped - static inline procs cannot work with '--noHeader | -H'
# proc 'mbedtls_cipher_get_operation' skipped - static inline procs cannot work with '--noHeader | -H'


{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}

defineEnum(mbedtls_cipher_id_t)
defineEnum(mbedtls_cipher_type_t)
defineEnum(mbedtls_cipher_mode_t)
defineEnum(mbedtls_cipher_padding_t)
defineEnum(mbedtls_operation_t)
defineEnum(Enum_cipherh1)

const
  MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE* = -0x00006080
  MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA* = -0x00006100
  MBEDTLS_ERR_CIPHER_ALLOC_FAILED* = -0x00006180
  MBEDTLS_ERR_CIPHER_INVALID_PADDING* = -0x00006200
  MBEDTLS_ERR_CIPHER_FULL_BLOCK_EXPECTED* = -0x00006280
  MBEDTLS_ERR_CIPHER_AUTH_FAILED* = -0x00006300
  MBEDTLS_ERR_CIPHER_INVALID_CONTEXT* = -0x00006380
  MBEDTLS_CIPHER_VARIABLE_IV_LEN* = 0x00000001
  MBEDTLS_CIPHER_VARIABLE_KEY_LEN* = 0x00000002
  MBEDTLS_CIPHER_ID_NONE* = (0).mbedtls_cipher_id_t
  MBEDTLS_CIPHER_ID_NULL* = (MBEDTLS_CIPHER_ID_NONE + 1).mbedtls_cipher_id_t
  MBEDTLS_CIPHER_ID_AES* = (MBEDTLS_CIPHER_ID_NULL + 1).mbedtls_cipher_id_t
  MBEDTLS_CIPHER_ID_DES* = (MBEDTLS_CIPHER_ID_AES + 1).mbedtls_cipher_id_t
  MBEDTLS_CIPHER_ID_3DES* = (MBEDTLS_CIPHER_ID_DES + 1).mbedtls_cipher_id_t
  MBEDTLS_CIPHER_ID_CAMELLIA* = (MBEDTLS_CIPHER_ID_3DES + 1).mbedtls_cipher_id_t
  MBEDTLS_CIPHER_ID_ARIA* = (MBEDTLS_CIPHER_ID_CAMELLIA + 1).mbedtls_cipher_id_t
  MBEDTLS_CIPHER_ID_CHACHA20* = (MBEDTLS_CIPHER_ID_ARIA + 1).mbedtls_cipher_id_t
  MBEDTLS_CIPHER_NONE* = (0).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_NULL* = (MBEDTLS_CIPHER_NONE + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_AES_128_ECB* = (MBEDTLS_CIPHER_NULL + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_AES_192_ECB* = (MBEDTLS_CIPHER_AES_128_ECB + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_AES_256_ECB* = (MBEDTLS_CIPHER_AES_192_ECB + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_AES_128_CBC* = (MBEDTLS_CIPHER_AES_256_ECB + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_AES_192_CBC* = (MBEDTLS_CIPHER_AES_128_CBC + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_AES_256_CBC* = (MBEDTLS_CIPHER_AES_192_CBC + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_AES_128_CFB128* = (MBEDTLS_CIPHER_AES_256_CBC + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_AES_192_CFB128* = (MBEDTLS_CIPHER_AES_128_CFB128 + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_AES_256_CFB128* = (MBEDTLS_CIPHER_AES_192_CFB128 + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_AES_128_CTR* = (MBEDTLS_CIPHER_AES_256_CFB128 + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_AES_192_CTR* = (MBEDTLS_CIPHER_AES_128_CTR + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_AES_256_CTR* = (MBEDTLS_CIPHER_AES_192_CTR + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_AES_128_GCM* = (MBEDTLS_CIPHER_AES_256_CTR + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_AES_192_GCM* = (MBEDTLS_CIPHER_AES_128_GCM + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_AES_256_GCM* = (MBEDTLS_CIPHER_AES_192_GCM + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_CAMELLIA_128_ECB* = (MBEDTLS_CIPHER_AES_256_GCM + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_CAMELLIA_192_ECB* = (MBEDTLS_CIPHER_CAMELLIA_128_ECB + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_CAMELLIA_256_ECB* = (MBEDTLS_CIPHER_CAMELLIA_192_ECB + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_CAMELLIA_128_CBC* = (MBEDTLS_CIPHER_CAMELLIA_256_ECB + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_CAMELLIA_192_CBC* = (MBEDTLS_CIPHER_CAMELLIA_128_CBC + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_CAMELLIA_256_CBC* = (MBEDTLS_CIPHER_CAMELLIA_192_CBC + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_CAMELLIA_128_CFB128* = (MBEDTLS_CIPHER_CAMELLIA_256_CBC + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_CAMELLIA_192_CFB128* = (MBEDTLS_CIPHER_CAMELLIA_128_CFB128 + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_CAMELLIA_256_CFB128* = (MBEDTLS_CIPHER_CAMELLIA_192_CFB128 + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_CAMELLIA_128_CTR* = (MBEDTLS_CIPHER_CAMELLIA_256_CFB128 + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_CAMELLIA_192_CTR* = (MBEDTLS_CIPHER_CAMELLIA_128_CTR + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_CAMELLIA_256_CTR* = (MBEDTLS_CIPHER_CAMELLIA_192_CTR + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_CAMELLIA_128_GCM* = (MBEDTLS_CIPHER_CAMELLIA_256_CTR + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_CAMELLIA_192_GCM* = (MBEDTLS_CIPHER_CAMELLIA_128_GCM + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_CAMELLIA_256_GCM* = (MBEDTLS_CIPHER_CAMELLIA_192_GCM + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_DES_ECB* = (MBEDTLS_CIPHER_CAMELLIA_256_GCM + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_DES_CBC* = (MBEDTLS_CIPHER_DES_ECB + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_DES_EDE_ECB* = (MBEDTLS_CIPHER_DES_CBC + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_DES_EDE_CBC* = (MBEDTLS_CIPHER_DES_EDE_ECB + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_DES_EDE3_ECB* = (MBEDTLS_CIPHER_DES_EDE_CBC + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_DES_EDE3_CBC* = (MBEDTLS_CIPHER_DES_EDE3_ECB + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_AES_128_CCM* = (MBEDTLS_CIPHER_DES_EDE3_CBC + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_AES_192_CCM* = (MBEDTLS_CIPHER_AES_128_CCM + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_AES_256_CCM* = (MBEDTLS_CIPHER_AES_192_CCM + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_AES_128_CCM_STAR_NO_TAG* = (MBEDTLS_CIPHER_AES_256_CCM + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_AES_192_CCM_STAR_NO_TAG* = (
      MBEDTLS_CIPHER_AES_128_CCM_STAR_NO_TAG + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_AES_256_CCM_STAR_NO_TAG* = (
      MBEDTLS_CIPHER_AES_192_CCM_STAR_NO_TAG + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_CAMELLIA_128_CCM* = (MBEDTLS_CIPHER_AES_256_CCM_STAR_NO_TAG + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_CAMELLIA_192_CCM* = (MBEDTLS_CIPHER_CAMELLIA_128_CCM + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_CAMELLIA_256_CCM* = (MBEDTLS_CIPHER_CAMELLIA_192_CCM + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_CAMELLIA_128_CCM_STAR_NO_TAG* = (
      MBEDTLS_CIPHER_CAMELLIA_256_CCM + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_CAMELLIA_192_CCM_STAR_NO_TAG* = (
      MBEDTLS_CIPHER_CAMELLIA_128_CCM_STAR_NO_TAG + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_CAMELLIA_256_CCM_STAR_NO_TAG* = (
      MBEDTLS_CIPHER_CAMELLIA_192_CCM_STAR_NO_TAG + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_ARIA_128_ECB* = (MBEDTLS_CIPHER_CAMELLIA_256_CCM_STAR_NO_TAG +
      1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_ARIA_192_ECB* = (MBEDTLS_CIPHER_ARIA_128_ECB + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_ARIA_256_ECB* = (MBEDTLS_CIPHER_ARIA_192_ECB + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_ARIA_128_CBC* = (MBEDTLS_CIPHER_ARIA_256_ECB + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_ARIA_192_CBC* = (MBEDTLS_CIPHER_ARIA_128_CBC + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_ARIA_256_CBC* = (MBEDTLS_CIPHER_ARIA_192_CBC + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_ARIA_128_CFB128* = (MBEDTLS_CIPHER_ARIA_256_CBC + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_ARIA_192_CFB128* = (MBEDTLS_CIPHER_ARIA_128_CFB128 + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_ARIA_256_CFB128* = (MBEDTLS_CIPHER_ARIA_192_CFB128 + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_ARIA_128_CTR* = (MBEDTLS_CIPHER_ARIA_256_CFB128 + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_ARIA_192_CTR* = (MBEDTLS_CIPHER_ARIA_128_CTR + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_ARIA_256_CTR* = (MBEDTLS_CIPHER_ARIA_192_CTR + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_ARIA_128_GCM* = (MBEDTLS_CIPHER_ARIA_256_CTR + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_ARIA_192_GCM* = (MBEDTLS_CIPHER_ARIA_128_GCM + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_ARIA_256_GCM* = (MBEDTLS_CIPHER_ARIA_192_GCM + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_ARIA_128_CCM* = (MBEDTLS_CIPHER_ARIA_256_GCM + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_ARIA_192_CCM* = (MBEDTLS_CIPHER_ARIA_128_CCM + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_ARIA_256_CCM* = (MBEDTLS_CIPHER_ARIA_192_CCM + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_ARIA_128_CCM_STAR_NO_TAG* = (MBEDTLS_CIPHER_ARIA_256_CCM + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_ARIA_192_CCM_STAR_NO_TAG* = (
      MBEDTLS_CIPHER_ARIA_128_CCM_STAR_NO_TAG + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_ARIA_256_CCM_STAR_NO_TAG* = (
      MBEDTLS_CIPHER_ARIA_192_CCM_STAR_NO_TAG + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_AES_128_OFB* = (MBEDTLS_CIPHER_ARIA_256_CCM_STAR_NO_TAG + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_AES_192_OFB* = (MBEDTLS_CIPHER_AES_128_OFB + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_AES_256_OFB* = (MBEDTLS_CIPHER_AES_192_OFB + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_AES_128_XTS* = (MBEDTLS_CIPHER_AES_256_OFB + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_AES_256_XTS* = (MBEDTLS_CIPHER_AES_128_XTS + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_CHACHA20* = (MBEDTLS_CIPHER_AES_256_XTS + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_CHACHA20_POLY1305* = (MBEDTLS_CIPHER_CHACHA20 + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_AES_128_KW* = (MBEDTLS_CIPHER_CHACHA20_POLY1305 + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_AES_192_KW* = (MBEDTLS_CIPHER_AES_128_KW + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_AES_256_KW* = (MBEDTLS_CIPHER_AES_192_KW + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_AES_128_KWP* = (MBEDTLS_CIPHER_AES_256_KW + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_AES_192_KWP* = (MBEDTLS_CIPHER_AES_128_KWP + 1).mbedtls_cipher_type_t
  MBEDTLS_CIPHER_AES_256_KWP* = (MBEDTLS_CIPHER_AES_192_KWP + 1).mbedtls_cipher_type_t
  MBEDTLS_MODE_NONE* = (0).mbedtls_cipher_mode_t
  MBEDTLS_MODE_ECB* = (MBEDTLS_MODE_NONE + 1).mbedtls_cipher_mode_t
  MBEDTLS_MODE_CBC* = (MBEDTLS_MODE_ECB + 1).mbedtls_cipher_mode_t
  MBEDTLS_MODE_CFB* = (MBEDTLS_MODE_CBC + 1).mbedtls_cipher_mode_t
  MBEDTLS_MODE_OFB* = (MBEDTLS_MODE_CFB + 1).mbedtls_cipher_mode_t
  MBEDTLS_MODE_CTR* = (MBEDTLS_MODE_OFB + 1).mbedtls_cipher_mode_t
  MBEDTLS_MODE_GCM* = (MBEDTLS_MODE_CTR + 1).mbedtls_cipher_mode_t
  MBEDTLS_MODE_STREAM* = (MBEDTLS_MODE_GCM + 1).mbedtls_cipher_mode_t
  MBEDTLS_MODE_CCM* = (MBEDTLS_MODE_STREAM + 1).mbedtls_cipher_mode_t
  MBEDTLS_MODE_CCM_STAR_NO_TAG* = (MBEDTLS_MODE_CCM + 1).mbedtls_cipher_mode_t
  MBEDTLS_MODE_XTS* = (MBEDTLS_MODE_CCM_STAR_NO_TAG + 1).mbedtls_cipher_mode_t
  MBEDTLS_MODE_CHACHAPOLY* = (MBEDTLS_MODE_XTS + 1).mbedtls_cipher_mode_t
  MBEDTLS_MODE_KW* = (MBEDTLS_MODE_CHACHAPOLY + 1).mbedtls_cipher_mode_t
  MBEDTLS_MODE_KWP* = (MBEDTLS_MODE_KW + 1).mbedtls_cipher_mode_t
  MBEDTLS_PADDING_PKCS7* = (0).mbedtls_cipher_padding_t
  MBEDTLS_PADDING_ONE_AND_ZEROS* = (MBEDTLS_PADDING_PKCS7 + 1).mbedtls_cipher_padding_t
  MBEDTLS_PADDING_ZEROS_AND_LEN* = (MBEDTLS_PADDING_ONE_AND_ZEROS + 1).mbedtls_cipher_padding_t
  MBEDTLS_PADDING_ZEROS* = (MBEDTLS_PADDING_ZEROS_AND_LEN + 1).mbedtls_cipher_padding_t
  MBEDTLS_PADDING_NONE* = (MBEDTLS_PADDING_ZEROS + 1).mbedtls_cipher_padding_t
  MBEDTLS_OPERATION_NONE* = (-1).mbedtls_operation_t
  MBEDTLS_DECRYPT* = (0).mbedtls_operation_t
  MBEDTLS_ENCRYPT* = (MBEDTLS_DECRYPT + 1).mbedtls_operation_t
  MBEDTLS_KEY_LENGTH_NONE* = (0).cint
  MBEDTLS_KEY_LENGTH_DES* = (64).cint
  MBEDTLS_KEY_LENGTH_DES_EDE* = (128).cint
  MBEDTLS_KEY_LENGTH_DES_EDE3* = (192).cint
  MBEDTLS_MAX_IV_LENGTH* = 16
  MBEDTLS_MAX_BLOCK_LENGTH* = 16
  MBEDTLS_MAX_KEY_LENGTH* = 64
type
  mbedtls_cipher_base_t* {.incompleteStruct.} = object
  mbedtls_cmac_context_t* {.incompleteStruct.} = object
  mbedtls_cipher_info_t* {.bycopy.} = object
    private_type*: mbedtls_cipher_type_t
    private_mode*: mbedtls_cipher_mode_t
    private_key_bitlen*: cuint
    private_name*: cstring
    private_iv_size*: cuint
    private_flags*: cint
    private_block_size*: cuint
    private_base*: ptr mbedtls_cipher_base_t

  mbedtls_cipher_context_t* {.bycopy.} = object
    private_cipher_info*: ptr mbedtls_cipher_info_t
    private_key_bitlen*: cint
    private_operation*: mbedtls_operation_t
    private_add_padding*: proc (output: ptr byte; olen: uint; data_len: uint) {.
        cdecl.}
    private_get_padding*: proc (input: ptr byte; ilen: uint;
                                data_len: ptr uint): cint {.cdecl.}
    private_unprocessed_data*: array[16, byte]
    private_unprocessed_len*: uint
    private_iv*: array[16, byte]
    private_iv_size*: uint
    private_cipher_ctx*: pointer
    private_cmac_ctx*: ptr mbedtls_cmac_context_t

proc mbedtls_cipher_list*(): ptr cint {.importc, cdecl.}
proc mbedtls_cipher_info_from_string*(cipher_name: cstring): ptr mbedtls_cipher_info_t {.
    importc, cdecl.}
proc mbedtls_cipher_info_from_type*(cipher_type: mbedtls_cipher_type_t): ptr mbedtls_cipher_info_t {.
    importc, cdecl.}
proc mbedtls_cipher_info_from_values*(cipher_id: mbedtls_cipher_id_t;
                                      key_bitlen: cint;
                                      mode: mbedtls_cipher_mode_t): ptr mbedtls_cipher_info_t {.
    importc, cdecl.}
proc mbedtls_cipher_init*(ctx: ptr mbedtls_cipher_context_t) {.importc, cdecl.}
proc mbedtls_cipher_free*(ctx: ptr mbedtls_cipher_context_t) {.importc, cdecl.}
proc mbedtls_cipher_setup*(ctx: ptr mbedtls_cipher_context_t;
                           cipher_info: ptr mbedtls_cipher_info_t): cint {.
    importc, cdecl.}
proc mbedtls_cipher_setkey*(ctx: ptr mbedtls_cipher_context_t; key: ptr byte;
                            key_bitlen: cint; operation: mbedtls_operation_t): cint {.
    importc, cdecl.}
proc mbedtls_cipher_set_padding_mode*(ctx: ptr mbedtls_cipher_context_t;
                                      mode: mbedtls_cipher_padding_t): cint {.
    importc, cdecl.}
proc mbedtls_cipher_set_iv*(ctx: ptr mbedtls_cipher_context_t; iv: ptr byte;
                            iv_len: uint): cint {.importc, cdecl.}
proc mbedtls_cipher_reset*(ctx: ptr mbedtls_cipher_context_t): cint {.importc,
    cdecl.}
proc mbedtls_cipher_update_ad*(ctx: ptr mbedtls_cipher_context_t;
                               ad: ptr byte; ad_len: uint): cint {.importc,
    cdecl.}
proc mbedtls_cipher_update*(ctx: ptr mbedtls_cipher_context_t;
                            input: ptr byte; ilen: uint; output: ptr byte;
                            olen: ptr uint): cint {.importc, cdecl.}
proc mbedtls_cipher_finish*(ctx: ptr mbedtls_cipher_context_t;
                            output: ptr byte; olen: ptr uint): cint {.importc,
    cdecl.}
proc mbedtls_cipher_write_tag*(ctx: ptr mbedtls_cipher_context_t;
                               tag: ptr byte; tag_len: uint): cint {.importc,
    cdecl.}
proc mbedtls_cipher_check_tag*(ctx: ptr mbedtls_cipher_context_t;
                               tag: ptr byte; tag_len: uint): cint {.importc,
    cdecl.}
proc mbedtls_cipher_crypt*(ctx: ptr mbedtls_cipher_context_t; iv: ptr byte;
                           iv_len: uint; input: ptr byte; ilen: uint;
                           output: ptr byte; olen: ptr uint): cint {.importc,
    cdecl.}
proc mbedtls_cipher_auth_encrypt_ext*(ctx: ptr mbedtls_cipher_context_t;
                                      iv: ptr byte; iv_len: uint;
                                      ad: ptr byte; ad_len: uint;
                                      input: ptr byte; ilen: uint;
                                      output: ptr byte; output_len: uint;
                                      olen: ptr uint; tag_len: uint): cint {.
    importc, cdecl.}
proc mbedtls_cipher_auth_decrypt_ext*(ctx: ptr mbedtls_cipher_context_t;
                                      iv: ptr byte; iv_len: uint;
                                      ad: ptr byte; ad_len: uint;
                                      input: ptr byte; ilen: uint;
                                      output: ptr byte; output_len: uint;
                                      olen: ptr uint; tag_len: uint): cint {.
    importc, cdecl.}
{.pop.}
