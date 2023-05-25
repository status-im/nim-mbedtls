{.used.}
import "../csources"
import "crypto_types"

# const 'PSA_ERROR_GENERIC_ERROR' has unsupported value '((psa_status_t)-132)'
# const 'PSA_ERROR_NOT_SUPPORTED' has unsupported value '((psa_status_t)-134)'
# const 'PSA_ERROR_NOT_PERMITTED' has unsupported value '((psa_status_t)-133)'
# const 'PSA_ERROR_BUFFER_TOO_SMALL' has unsupported value '((psa_status_t)-138)'
# const 'PSA_ERROR_ALREADY_EXISTS' has unsupported value '((psa_status_t)-139)'
# const 'PSA_ERROR_DOES_NOT_EXIST' has unsupported value '((psa_status_t)-140)'
# const 'PSA_ERROR_BAD_STATE' has unsupported value '((psa_status_t)-137)'
# const 'PSA_ERROR_INVALID_ARGUMENT' has unsupported value '((psa_status_t)-135)'
# const 'PSA_ERROR_INSUFFICIENT_MEMORY' has unsupported value '((psa_status_t)-141)'
# const 'PSA_ERROR_INSUFFICIENT_STORAGE' has unsupported value '((psa_status_t)-142)'
# const 'PSA_ERROR_COMMUNICATION_FAILURE' has unsupported value '((psa_status_t)-145)'
# const 'PSA_ERROR_STORAGE_FAILURE' has unsupported value '((psa_status_t)-146)'
# const 'PSA_ERROR_HARDWARE_FAILURE' has unsupported value '((psa_status_t)-147)'
# const 'PSA_ERROR_CORRUPTION_DETECTED' has unsupported value '((psa_status_t)-151)'
# const 'PSA_ERROR_INSUFFICIENT_ENTROPY' has unsupported value '((psa_status_t)-148)'
# const 'PSA_ERROR_INVALID_SIGNATURE' has unsupported value '((psa_status_t)-149)'
# const 'PSA_ERROR_INVALID_PADDING' has unsupported value '((psa_status_t)-150)'
# const 'PSA_ERROR_INSUFFICIENT_DATA' has unsupported value '((psa_status_t)-143)'
# const 'PSA_ERROR_INVALID_HANDLE' has unsupported value '((psa_status_t)-136)'
# const 'PSA_ERROR_DATA_CORRUPT' has unsupported value '((psa_status_t)-152)'
# const 'PSA_ERROR_DATA_INVALID' has unsupported value '((psa_status_t)-153)'
# const 'PSA_OPERATION_INCOMPLETE' has unsupported value '((psa_status_t)-248)'
# const 'PSA_ALG_RSA_PKCS1V15_SIGN_RAW' has unsupported value 'PSA_ALG_RSA_PKCS1V15_SIGN_BASE'
# const 'PSA_ALG_ECDSA_ANY' has unsupported value 'PSA_ALG_ECDSA_BASE'
# const 'PSA_INTERRUPTIBLE_MAX_OPS_UNLIMITED' has unsupported value 'UINT32_MAX'

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}

const
  PSA_SUCCESS* = (cast[psa_status_t](0))
  PSA_KEY_TYPE_NONE* = (cast[psa_key_type_t](0x00000000))
  PSA_KEY_TYPE_VENDOR_FLAG* = (cast[psa_key_type_t](0x00008000))
  PSA_KEY_TYPE_CATEGORY_MASK* = (cast[psa_key_type_t](0x00007000))
  PSA_KEY_TYPE_CATEGORY_RAW* = (cast[psa_key_type_t](0x00001000))
  PSA_KEY_TYPE_CATEGORY_SYMMETRIC* = (cast[psa_key_type_t](0x00002000))
  PSA_KEY_TYPE_CATEGORY_PUBLIC_KEY* = (cast[psa_key_type_t](0x00004000))
  PSA_KEY_TYPE_CATEGORY_KEY_PAIR* = (cast[psa_key_type_t](0x00007000))
  PSA_KEY_TYPE_CATEGORY_FLAG_PAIR* = (cast[psa_key_type_t](0x00003000))
  PSA_KEY_TYPE_RAW_DATA* = (cast[psa_key_type_t](0x00001001))
  PSA_KEY_TYPE_HMAC* = (cast[psa_key_type_t](0x00001100))
  PSA_KEY_TYPE_DERIVE* = (cast[psa_key_type_t](0x00001200))
  PSA_KEY_TYPE_PASSWORD* = (cast[psa_key_type_t](0x00001203))
  PSA_KEY_TYPE_PASSWORD_HASH* = (cast[psa_key_type_t](0x00001205))
  PSA_KEY_TYPE_PEPPER* = (cast[psa_key_type_t](0x00001206))
  PSA_KEY_TYPE_AES* = (cast[psa_key_type_t](0x00002400))
  PSA_KEY_TYPE_ARIA* = (cast[psa_key_type_t](0x00002406))
  PSA_KEY_TYPE_DES* = (cast[psa_key_type_t](0x00002301))
  PSA_KEY_TYPE_CAMELLIA* = (cast[psa_key_type_t](0x00002403))
  PSA_KEY_TYPE_CHACHA20* = (cast[psa_key_type_t](0x00002004))
  PSA_KEY_TYPE_RSA_PUBLIC_KEY* = (cast[psa_key_type_t](0x00004001))
  PSA_KEY_TYPE_RSA_KEY_PAIR* = (cast[psa_key_type_t](0x00007001))
  PSA_KEY_TYPE_ECC_PUBLIC_KEY_BASE* = (cast[psa_key_type_t](0x00004100))
  PSA_KEY_TYPE_ECC_KEY_PAIR_BASE* = (cast[psa_key_type_t](0x00007100))
  PSA_KEY_TYPE_ECC_CURVE_MASK* = (cast[psa_key_type_t](0x000000FF))
  PSA_ECC_FAMILY_SECP_K1* = (cast[psa_ecc_family_t](0x00000017))
  PSA_ECC_FAMILY_SECP_R1* = (cast[psa_ecc_family_t](0x00000012))
  PSA_ECC_FAMILY_SECP_R2* = (cast[psa_ecc_family_t](0x0000001B))
  PSA_ECC_FAMILY_SECT_K1* = (cast[psa_ecc_family_t](0x00000027))
  PSA_ECC_FAMILY_SECT_R1* = (cast[psa_ecc_family_t](0x00000022))
  PSA_ECC_FAMILY_SECT_R2* = (cast[psa_ecc_family_t](0x0000002B))
  PSA_ECC_FAMILY_BRAINPOOL_P_R1* = (cast[psa_ecc_family_t](0x00000030))
  PSA_ECC_FAMILY_MONTGOMERY* = (cast[psa_ecc_family_t](0x00000041))
  PSA_ECC_FAMILY_TWISTED_EDWARDS* = (cast[psa_ecc_family_t](0x00000042))
  PSA_KEY_TYPE_DH_PUBLIC_KEY_BASE* = (cast[psa_key_type_t](0x00004200))
  PSA_KEY_TYPE_DH_KEY_PAIR_BASE* = (cast[psa_key_type_t](0x00007200))
  PSA_KEY_TYPE_DH_GROUP_MASK* = (cast[psa_key_type_t](0x000000FF))
  PSA_DH_FAMILY_RFC7919* = (cast[psa_dh_family_t](0x00000003))
  PSA_ALG_VENDOR_FLAG* = (cast[psa_algorithm_t](0x80000000))
  PSA_ALG_CATEGORY_MASK* = (cast[psa_algorithm_t](0x7F000000))
  PSA_ALG_CATEGORY_HASH* = (cast[psa_algorithm_t](0x02000000))
  PSA_ALG_CATEGORY_MAC* = (cast[psa_algorithm_t](0x03000000))
  PSA_ALG_CATEGORY_CIPHER* = (cast[psa_algorithm_t](0x04000000))
  PSA_ALG_CATEGORY_AEAD* = (cast[psa_algorithm_t](0x05000000))
  PSA_ALG_CATEGORY_SIGN* = (cast[psa_algorithm_t](0x06000000))
  PSA_ALG_CATEGORY_ASYMMETRIC_ENCRYPTION* = (cast[psa_algorithm_t](0x07000000))
  PSA_ALG_CATEGORY_KEY_DERIVATION* = (cast[psa_algorithm_t](0x08000000))
  PSA_ALG_CATEGORY_KEY_AGREEMENT* = (cast[psa_algorithm_t](0x09000000))
  PSA_ALG_NONE* = (cast[psa_algorithm_t](0))
  PSA_ALG_HASH_MASK* = (cast[psa_algorithm_t](0x000000FF))
  PSA_ALG_MD5* = (cast[psa_algorithm_t](0x02000003))
  PSA_ALG_RIPEMD160* = (cast[psa_algorithm_t](0x02000004))
  PSA_ALG_SHA_1* = (cast[psa_algorithm_t](0x02000005))
  PSA_ALG_SHA_224* = (cast[psa_algorithm_t](0x02000008))
  PSA_ALG_SHA_256* = (cast[psa_algorithm_t](0x02000009))
  PSA_ALG_SHA_384* = (cast[psa_algorithm_t](0x0200000A))
  PSA_ALG_SHA_512* = (cast[psa_algorithm_t](0x0200000B))
  PSA_ALG_SHA_512_224* = (cast[psa_algorithm_t](0x0200000C))
  PSA_ALG_SHA_512_256* = (cast[psa_algorithm_t](0x0200000D))
  PSA_ALG_SHA3_224* = (cast[psa_algorithm_t](0x02000010))
  PSA_ALG_SHA3_256* = (cast[psa_algorithm_t](0x02000011))
  PSA_ALG_SHA3_384* = (cast[psa_algorithm_t](0x02000012))
  PSA_ALG_SHA3_512* = (cast[psa_algorithm_t](0x02000013))
  PSA_ALG_SHAKE256_512* = (cast[psa_algorithm_t](0x02000015))
  PSA_ALG_ANY_HASH* = (cast[psa_algorithm_t](0x020000FF))
  PSA_ALG_MAC_SUBCATEGORY_MASK* = (cast[psa_algorithm_t](0x00C00000))
  PSA_ALG_HMAC_BASE* = (cast[psa_algorithm_t](0x03800000))
  PSA_ALG_MAC_TRUNCATION_MASK* = (cast[psa_algorithm_t](0x003F0000))
  PSA_MAC_TRUNCATION_OFFSET* = 16
  PSA_ALG_MAC_AT_LEAST_THIS_LENGTH_FLAG* = (cast[psa_algorithm_t](0x00008000))
  PSA_ALG_CIPHER_MAC_BASE* = (cast[psa_algorithm_t](0x03C00000))
  PSA_ALG_CBC_MAC* = (cast[psa_algorithm_t](0x03C00100))
  PSA_ALG_CMAC* = (cast[psa_algorithm_t](0x03C00200))
  PSA_ALG_CIPHER_STREAM_FLAG* = (cast[psa_algorithm_t](0x00800000))
  PSA_ALG_CIPHER_FROM_BLOCK_FLAG* = (cast[psa_algorithm_t](0x00400000))
  PSA_ALG_STREAM_CIPHER* = (cast[psa_algorithm_t](0x04800100))
  PSA_ALG_CTR* = (cast[psa_algorithm_t](0x04C01000))
  PSA_ALG_CFB* = (cast[psa_algorithm_t](0x04C01100))
  PSA_ALG_OFB* = (cast[psa_algorithm_t](0x04C01200))
  PSA_ALG_XTS* = (cast[psa_algorithm_t](0x0440FF00))
  PSA_ALG_ECB_NO_PADDING* = (cast[psa_algorithm_t](0x04404400))
  PSA_ALG_CBC_NO_PADDING* = (cast[psa_algorithm_t](0x04404000))
  PSA_ALG_CBC_PKCS7* = (cast[psa_algorithm_t](0x04404100))
  PSA_ALG_AEAD_FROM_BLOCK_FLAG* = (cast[psa_algorithm_t](0x00400000))
  PSA_ALG_CCM* = (cast[psa_algorithm_t](0x05500100))
  PSA_ALG_CCM_STAR_NO_TAG* = (cast[psa_algorithm_t](0x04C01300))
  PSA_ALG_GCM* = (cast[psa_algorithm_t](0x05500200))
  PSA_ALG_CHACHA20_POLY1305* = (cast[psa_algorithm_t](0x05100500))
  PSA_ALG_AEAD_TAG_LENGTH_MASK* = (cast[psa_algorithm_t](0x003F0000))
  PSA_AEAD_TAG_LENGTH_OFFSET* = 16
  PSA_ALG_AEAD_AT_LEAST_THIS_LENGTH_FLAG* = (cast[psa_algorithm_t](0x00008000))
  PSA_ALG_RSA_PKCS1V15_SIGN_BASE* = (cast[psa_algorithm_t](0x06000200))
  PSA_ALG_RSA_PSS_BASE* = (cast[psa_algorithm_t](0x06000300))
  PSA_ALG_RSA_PSS_ANY_SALT_BASE* = (cast[psa_algorithm_t](0x06001300))
  PSA_ALG_ECDSA_BASE* = (cast[psa_algorithm_t](0x06000600))
  PSA_ALG_DETERMINISTIC_ECDSA_BASE* = (cast[psa_algorithm_t](0x06000700))
  PSA_ALG_ECDSA_DETERMINISTIC_FLAG* = (cast[psa_algorithm_t](0x00000100))
  PSA_ALG_PURE_EDDSA* = (cast[psa_algorithm_t](0x06000800))
  PSA_ALG_HASH_EDDSA_BASE* = (cast[psa_algorithm_t](0x06000900))
  PSA_ALG_ED25519PH* = (PSA_ALG_HASH_EDDSA_BASE or
      typeof(PSA_ALG_HASH_EDDSA_BASE)((PSA_ALG_SHA_512 and
      typeof(PSA_ALG_HASH_EDDSA_BASE)(PSA_ALG_HASH_MASK))))
  PSA_ALG_ED448PH* = (PSA_ALG_HASH_EDDSA_BASE or
      typeof(PSA_ALG_HASH_EDDSA_BASE)((PSA_ALG_SHAKE256_512 and
      typeof(PSA_ALG_HASH_EDDSA_BASE)(PSA_ALG_HASH_MASK))))
  PSA_ALG_RSA_PKCS1V15_CRYPT* = (cast[psa_algorithm_t](0x07000200))
  PSA_ALG_RSA_OAEP_BASE* = (cast[psa_algorithm_t](0x07000300))
  PSA_ALG_HKDF_BASE* = (cast[psa_algorithm_t](0x08000100))
  PSA_ALG_HKDF_EXTRACT_BASE* = (cast[psa_algorithm_t](0x08000400))
  PSA_ALG_HKDF_EXPAND_BASE* = (cast[psa_algorithm_t](0x08000500))
  PSA_ALG_TLS12_PRF_BASE* = (cast[psa_algorithm_t](0x08000200))
  PSA_ALG_TLS12_PSK_TO_MS_BASE* = (cast[psa_algorithm_t](0x08000300))
  PSA_ALG_TLS12_ECJPAKE_TO_PMS* = (cast[psa_algorithm_t](0x08000609))
  PSA_ALG_KEY_DERIVATION_STRETCHING_FLAG* = (cast[psa_algorithm_t](0x00800000))
  PSA_ALG_PBKDF2_HMAC_BASE* = (cast[psa_algorithm_t](0x08800100))
  PSA_ALG_PBKDF2_AES_CMAC_PRF_128* = (cast[psa_algorithm_t](0x08800200))
  PSA_ALG_KEY_DERIVATION_MASK* = (cast[psa_algorithm_t](0xFE00FFFF))
  PSA_ALG_KEY_AGREEMENT_MASK* = (cast[psa_algorithm_t](0xFFFF0000))
  PSA_ALG_FFDH* = (cast[psa_algorithm_t](0x09010000))
  PSA_ALG_ECDH* = (cast[psa_algorithm_t](0x09020000))
  PSA_KEY_LIFETIME_VOLATILE* = (cast[psa_key_lifetime_t](0x00000000))
  PSA_KEY_LIFETIME_PERSISTENT* = (cast[psa_key_lifetime_t](0x00000001))
  PSA_KEY_PERSISTENCE_VOLATILE* = (cast[psa_key_persistence_t](0x00000000))
  PSA_KEY_PERSISTENCE_DEFAULT* = (cast[psa_key_persistence_t](0x00000001))
  PSA_KEY_PERSISTENCE_READ_ONLY* = (cast[psa_key_persistence_t](0x000000FF))
  PSA_KEY_LOCATION_LOCAL_STORAGE* = (cast[psa_key_location_t](0x00000000))
  PSA_KEY_LOCATION_VENDOR_FLAG* = (cast[psa_key_location_t](0x00800000))
  PSA_KEY_ID_NULL* = (cast[psa_key_id_t](0))
  PSA_KEY_ID_USER_MIN* = (cast[psa_key_id_t](0x00000001))
  PSA_KEY_ID_USER_MAX* = (cast[psa_key_id_t](0x3FFFFFFF))
  PSA_KEY_ID_VENDOR_MIN* = (cast[psa_key_id_t](0x40000000))
  PSA_KEY_ID_VENDOR_MAX* = (cast[psa_key_id_t](0x7FFFFFFF))
  MBEDTLS_SVC_KEY_ID_INIT* = (cast[psa_key_id_t](0))
  PSA_KEY_USAGE_EXPORT* = (cast[psa_key_usage_t](0x00000001))
  PSA_KEY_USAGE_COPY* = (cast[psa_key_usage_t](0x00000002))
  PSA_KEY_USAGE_ENCRYPT* = (cast[psa_key_usage_t](0x00000100))
  PSA_KEY_USAGE_DECRYPT* = (cast[psa_key_usage_t](0x00000200))
  PSA_KEY_USAGE_SIGN_MESSAGE* = (cast[psa_key_usage_t](0x00000400))
  PSA_KEY_USAGE_VERIFY_MESSAGE* = (cast[psa_key_usage_t](0x00000800))
  PSA_KEY_USAGE_SIGN_HASH* = (cast[psa_key_usage_t](0x00001000))
  PSA_KEY_USAGE_VERIFY_HASH* = (cast[psa_key_usage_t](0x00002000))
  PSA_KEY_USAGE_DERIVE* = (cast[psa_key_usage_t](0x00004000))
  PSA_KEY_USAGE_VERIFY_DERIVATION* = (cast[psa_key_usage_t](0x00008000))
  PSA_KEY_DERIVATION_INPUT_SECRET* = (
    cast[psa_key_derivation_step_t](0x00000101))
  PSA_KEY_DERIVATION_INPUT_PASSWORD* = (
    cast[psa_key_derivation_step_t](0x00000102))
  PSA_KEY_DERIVATION_INPUT_OTHER_SECRET* = (
    cast[psa_key_derivation_step_t](0x00000103))
  PSA_KEY_DERIVATION_INPUT_LABEL* = (cast[psa_key_derivation_step_t](0x00000201))
  PSA_KEY_DERIVATION_INPUT_SALT* = (cast[psa_key_derivation_step_t](0x00000202))
  PSA_KEY_DERIVATION_INPUT_INFO* = (cast[psa_key_derivation_step_t](0x00000203))
  PSA_KEY_DERIVATION_INPUT_SEED* = (cast[psa_key_derivation_step_t](0x00000204))
  PSA_KEY_DERIVATION_INPUT_COST* = (cast[psa_key_derivation_step_t](0x00000205))
proc mbedtls_svc_key_id_make*(unused: cuint; key_id: psa_key_id_t): mbedtls_svc_key_id_t {.
    importc, cdecl.}
proc mbedtls_svc_key_id_equal*(id1: mbedtls_svc_key_id_t;
                               id2: mbedtls_svc_key_id_t): cint {.importc,
    cdecl.}
proc mbedtls_svc_key_id_is_null*(key: mbedtls_svc_key_id_t): cint {.importc,
    cdecl.}
{.pop.}
