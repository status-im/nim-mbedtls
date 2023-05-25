{.used.}
import "../csources"
import "../md5"
import "../ripemd160"
import "../sha1"
import "../sha256"
import "../sha512"
import "../cipher"
import "../ccm"
import "../gcm"
import "../chachapoly"
import "../ecjpake"
import "../utils"

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.pragma: impcrypto_builtin_key_derivationHdr, header: "/home/lchenut/minnim/webrtc/mbedtls/include/psa/crypto_builtin_key_derivation.h".}
{.experimental: "codeReordering".}

defineEnum(psa_tls12_prf_key_derivation_state_t)

const
  PSA_TLS12_PRF_STATE_INIT* = (0).psa_tls12_prf_key_derivation_state_t
  PSA_TLS12_PRF_STATE_SEED_SET* = (PSA_TLS12_PRF_STATE_INIT + 1).psa_tls12_prf_key_derivation_state_t
  PSA_TLS12_PRF_STATE_OTHER_KEY_SET* = (PSA_TLS12_PRF_STATE_SEED_SET + 1).psa_tls12_prf_key_derivation_state_t
  PSA_TLS12_PRF_STATE_KEY_SET* = (PSA_TLS12_PRF_STATE_OTHER_KEY_SET + 1).psa_tls12_prf_key_derivation_state_t
  PSA_TLS12_PRF_STATE_LABEL_SET* = (PSA_TLS12_PRF_STATE_KEY_SET + 1).psa_tls12_prf_key_derivation_state_t
  PSA_TLS12_PRF_STATE_OUTPUT* = (PSA_TLS12_PRF_STATE_LABEL_SET + 1).psa_tls12_prf_key_derivation_state_t

{.experimental: "codeReordering".}

type
  psa_hkdf_key_derivation_t* {.bycopy.} = object
    private_info*: ptr uint8
    private_info_length*: uint
    private_offset_in_block*: uint8
    private_block_number*: uint8
    private_state* {.bitsize: 2.}: cuint
    private_info_set* {.bitsize: 1.}: cuint
    private_output_block*: array[64, uint8]
    private_prk*: array[64, uint8]
    private_hmac*: psa_mac_operation_s

  psa_tls12_ecjpake_to_pms_t* {.bycopy.} = object
    private_data*: array[32, uint8]

  psa_tls12_prf_key_derivation_s* {.bycopy.} = object
    private_left_in_block*: uint8
    private_block_number*: uint8
    private_state*: psa_tls12_prf_key_derivation_state_t
    private_secret*: ptr uint8
    private_secret_length*: uint
    private_seed*: ptr uint8
    private_seed_length*: uint
    private_label*: ptr uint8
    private_label_length*: uint
    private_other_secret*: ptr uint8
    private_other_secret_length*: uint
    private_Ai*: array[64, uint8]
    private_output_block*: array[64, uint8]

  psa_tls12_prf_key_derivation_t* {.importc.} = psa_tls12_prf_key_derivation_s
  psa_driver_key_derivation_context_t* {.union, bycopy.} = object
    dummy*: cuint
    private_hkdf*: psa_hkdf_key_derivation_t
    private_tls12_prf*: psa_tls12_prf_key_derivation_t
    private_tls12_ecjpake_to_pms*: psa_tls12_ecjpake_to_pms_t

  mbedtls_psa_hmac_operation_t* {.bycopy.} = object
    private_alg*: psa_algorithm_t
    hash_ctx*: psa_hash_operation_s
    private_opad*: array[128, uint8]

  Union_crypto_builtin_compositesh1* {.union, bycopy.} = object
    private_dummy*: cuint
    private_hmac*: mbedtls_psa_hmac_operation_t
    private_cmac*: mbedtls_cipher_context_t

  mbedtls_psa_mac_operation_t* {.bycopy.} = object
    private_alg*: psa_algorithm_t
    private_ctx*: Union_crypto_builtin_compositesh1

  Union_crypto_builtin_compositesh2* {.union, bycopy.} = object
    dummy*: cuint
    private_ccm*: mbedtls_ccm_context
    private_gcm*: mbedtls_gcm_context
    private_chachapoly*: mbedtls_chachapoly_context

  mbedtls_psa_aead_operation_t* {.bycopy.} = object
    private_alg*: psa_algorithm_t
    private_key_type*: psa_key_type_t
    private_is_encrypt* {.bitsize: 1.}: cuint
    private_tag_length*: uint8
    ctx*: Union_crypto_builtin_compositesh2

  mbedtls_psa_sign_hash_interruptible_operation_t* {.bycopy.} = object
    private_dummy*: cuint

  mbedtls_psa_verify_hash_interruptible_operation_t* {.bycopy.} = object
    private_dummy*: cuint

  Union_crypto_builtin_compositesh3* {.union, bycopy.} = object
    private_dummy*: cuint
    private_jpake*: mbedtls_ecjpake_context

  mbedtls_psa_pake_operation_t* {.bycopy.} = object
    private_alg*: psa_algorithm_t
    private_password*: ptr uint8
    private_password_len*: uint
    private_role*: uint8
    private_buffer*: array[((3 + typeof(3)(1) + typeof(3)(65) + typeof(3)(1) +
        typeof(3)(65) +
        typeof(3)(1) +
        typeof(3)(32)) *
        typeof(3)(2)), uint8]
    private_buffer_length*: uint
    private_buffer_offset*: uint
    private_ctx*: Union_crypto_builtin_compositesh3

  psa_driver_mac_context_t* {.union, bycopy.} = object
    dummy*: cuint
    mbedtls_ctx*: mbedtls_psa_mac_operation_t

  psa_driver_aead_context_t* {.union, bycopy.} = object
    dummy*: cuint
    mbedtls_ctx*: mbedtls_psa_aead_operation_t

  psa_driver_sign_hash_interruptible_context_t* {.union, bycopy.} = object
    dummy*: cuint
    mbedtls_ctx*: mbedtls_psa_sign_hash_interruptible_operation_t

  psa_driver_verify_hash_interruptible_context_t* {.union, bycopy.} = object
    dummy*: cuint
    mbedtls_ctx*: mbedtls_psa_verify_hash_interruptible_operation_t

  psa_driver_pake_context_t* {.union, bycopy.} = object
    dummy*: cuint
    mbedtls_ctx*: mbedtls_psa_pake_operation_t

  Union_crypto_builtin_primitivesh1* {.union, bycopy.} = object
    dummy*: cuint
    md5*: mbedtls_md5_context
    ripemd160*: mbedtls_ripemd160_context
    sha1*: mbedtls_sha1_context
    sha256*: mbedtls_sha256_context
    sha512*: mbedtls_sha512_context

  mbedtls_psa_hash_operation_t* {.bycopy.} = object
    private_alg*: psa_algorithm_t
    private_ctx*: Union_crypto_builtin_primitivesh1

  Union_crypto_builtin_primitivesh2* {.union, bycopy.} = object
    private_dummy*: cuint
    private_cipher*: mbedtls_cipher_context_t

  mbedtls_psa_cipher_operation_t* {.bycopy.} = object
    private_alg*: psa_algorithm_t
    private_iv_length*: uint8
    private_block_length*: uint8
    private_ctx*: Union_crypto_builtin_primitivesh2
  psa_driver_hash_context_t* {.union, bycopy.} = object
    dummy*: cuint
    mbedtls_ctx*: mbedtls_psa_hash_operation_t

  psa_driver_cipher_context_t* {.union, bycopy.} = object
    dummy*: cuint
    mbedtls_ctx*: mbedtls_psa_cipher_operation_t

  psa_hash_operation_s* {.bycopy.} = object
    private_id*: cuint
    private_ctx*: psa_driver_hash_context_t

  psa_cipher_operation_s* {.bycopy.} = object
    private_id*: cuint
    private_iv_required* {.bitsize: 1.}: cuint
    private_iv_set* {.bitsize: 1.}: cuint
    private_default_iv_length*: uint8
    private_ctx*: psa_driver_cipher_context_t

  psa_mac_operation_s* {.bycopy.} = object
    private_id*: cuint
    private_mac_size*: uint8
    private_is_sign* {.bitsize: 1.}: cuint
    private_ctx*: psa_driver_mac_context_t

  psa_aead_operation_s* {.bycopy.} = object
    private_id*: cuint
    private_alg*: psa_algorithm_t
    private_key_type*: psa_key_type_t
    private_ad_remaining*: uint
    private_body_remaining*: uint
    private_nonce_set* {.bitsize: 1.}: cuint
    private_lengths_set* {.bitsize: 1.}: cuint
    private_ad_started* {.bitsize: 1.}: cuint
    private_body_started* {.bitsize: 1.}: cuint
    private_is_encrypt* {.bitsize: 1.}: cuint
    private_ctx*: psa_driver_aead_context_t

  psa_key_derivation_s* {.bycopy.} = object
    private_alg*: psa_algorithm_t
    private_can_output_key* {.bitsize: 1.}: cuint
    private_capacity*: uint
    private_ctx*: psa_driver_key_derivation_context_t

  psa_key_policy_s* {.bycopy.} = object
    private_usage*: psa_key_usage_t
    private_alg*: psa_algorithm_t
    private_alg2*: psa_algorithm_t

  psa_key_policy_t* = psa_key_policy_s
  psa_key_bits_t* = uint16
  psa_key_attributes_flag_t* = uint16
  psa_core_key_attributes_t* {.bycopy.} = object
    private_type*: psa_key_type_t
    private_bits*: psa_key_bits_t
    private_lifetime*: psa_key_lifetime_t
    private_id*: mbedtls_svc_key_id_t
    private_policy*: psa_key_policy_t
    private_flags*: psa_key_attributes_flag_t

  psa_key_attributes_s* {.bycopy.} = object
    private_core*: psa_core_key_attributes_t
    private_domain_parameters*: pointer
    private_domain_parameters_size*: uint

  psa_sign_hash_interruptible_operation_s* {.bycopy.} = object
    private_id*: cuint
    private_ctx*: psa_driver_sign_hash_interruptible_context_t
    private_error_occurred* {.bitsize: 1.}: cuint
    private_num_ops*: uint32

  psa_verify_hash_interruptible_operation_s* {.bycopy.} = object
    private_id*: cuint
    private_ctx*: psa_driver_verify_hash_interruptible_context_t
    private_error_occurred* {.bitsize: 1.}: cuint
    private_num_ops*: uint32

  psa_status_t* = int32
  psa_key_type_t* = uint16
  psa_ecc_family_t* = uint8
  psa_dh_family_t* = uint8
  psa_algorithm_t* = uint32
  psa_key_lifetime_t* = uint32
  psa_key_persistence_t* = uint8
  psa_key_location_t* = uint32
  psa_key_id_t* = uint32
  mbedtls_svc_key_id_t* = psa_key_id_t
  psa_key_usage_t* = uint32
  psa_key_attributes_t* = psa_key_attributes_s
  psa_key_derivation_step_t* = uint16
{.pop.}
