import "../csources"
import "crypto_types"
{.compile: "./mbedtls/csources/library/psa_crypto_client.c".}

# const 'PSA_HASH_OPERATION_INIT' has unsupported value '{ 0, { 0 } }'
# const 'PSA_CIPHER_OPERATION_INIT' has unsupported value '{ 0, 0, 0, 0, { 0 } }'
# const 'PSA_MAC_OPERATION_INIT' has unsupported value '{ 0, 0, 0, { 0 } }'
# const 'PSA_AEAD_OPERATION_INIT' has unsupported value '{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, { 0 } }'
# const 'PSA_KEY_DERIVATION_OPERATION_INIT' has unsupported value '{ 0, 0, 0, { 0 } }'
# const 'PSA_KEY_POLICY_INIT' has unsupported value '{ 0, 0, 0 }'
# const 'PSA_KEY_BITS_TOO_LARGE' has unsupported value '((psa_key_bits_t) -1)'
# const 'PSA_CORE_KEY_ATTRIBUTES_INIT' has unsupported value '{ PSA_KEY_TYPE_NONE, 0, PSA_KEY_LIFETIME_VOLATILE, MBEDTLS_SVC_KEY_ID_INIT, PSA_KEY_POLICY_INIT, 0 }'
# const 'PSA_KEY_ATTRIBUTES_INIT' has unsupported value '{ PSA_CORE_KEY_ATTRIBUTES_INIT, NULL, 0 }'
# const 'PSA_SIGN_HASH_INTERRUPTIBLE_OPERATION_INIT' has unsupported value '{ 0, { 0 }, 0, 0 }'
# const 'PSA_VERIFY_HASH_INTERRUPTIBLE_OPERATION_INIT' has unsupported value '{ 0, { 0 }, 0, 0 }'

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}

const
  PSA_MAX_KEY_BITS* = 0x0000FFF8
  MBEDTLS_PSA_KA_FLAG_HAS_SLOT_NUMBER* = (
    cast[psa_key_attributes_flag_t](0x00000001))
  MBEDTLS_PSA_KA_MASK_EXTERNAL_ONLY* = (MBEDTLS_PSA_KA_FLAG_HAS_SLOT_NUMBER or
      typeof(MBEDTLS_PSA_KA_FLAG_HAS_SLOT_NUMBER)(0))
  MBEDTLS_PSA_KA_MASK_DUAL_USE* = (0)

proc psa_hash_operation_init*(): psa_hash_operation_s {.importc, cdecl.}
proc psa_cipher_operation_init*(): psa_cipher_operation_s {.importc, cdecl.}
proc psa_mac_operation_init*(): psa_mac_operation_s {.importc, cdecl.}
proc psa_aead_operation_init*(): psa_aead_operation_s {.importc, cdecl.}
proc psa_key_derivation_operation_init*(): psa_key_derivation_s {.importc,
    cdecl.}
proc psa_key_policy_init*(): psa_key_policy_s {.importc, cdecl.}
proc psa_key_attributes_init*(): psa_key_attributes_s {.importc, cdecl.}
proc psa_set_key_id*(attributes: ptr psa_key_attributes_t;
                     key: mbedtls_svc_key_id_t) {.importc, cdecl.}
proc psa_get_key_id*(attributes: ptr psa_key_attributes_t): mbedtls_svc_key_id_t {.
    importc, cdecl.}
proc psa_set_key_lifetime*(attributes: ptr psa_key_attributes_t;
                           lifetime: psa_key_lifetime_t) {.importc, cdecl.}
proc psa_get_key_lifetime*(attributes: ptr psa_key_attributes_t): psa_key_lifetime_t {.
    importc, cdecl.}
proc psa_extend_key_usage_flags*(usage_flags: ptr psa_key_usage_t) {.importc,
    cdecl.}
proc psa_set_key_usage_flags*(attributes: ptr psa_key_attributes_t;
                              usage_flags: psa_key_usage_t) {.importc, cdecl.}
proc psa_get_key_usage_flags*(attributes: ptr psa_key_attributes_t): psa_key_usage_t {.
    importc, cdecl.}
proc psa_set_key_algorithm*(attributes: ptr psa_key_attributes_t;
                            alg: psa_algorithm_t) {.importc, cdecl.}
proc psa_get_key_algorithm*(attributes: ptr psa_key_attributes_t): psa_algorithm_t {.
    importc, cdecl.}
proc psa_set_key_domain_parameters*(attributes: ptr psa_key_attributes_t;
                                    `type`: psa_key_type_t; data: ptr uint8;
                                    data_length: uint): psa_status_t {.importc,
    cdecl.}
proc psa_set_key_type*(attributes: ptr psa_key_attributes_t;
                       `type`: psa_key_type_t) {.importc, cdecl.}
proc psa_get_key_type*(attributes: ptr psa_key_attributes_t): psa_key_type_t {.
    importc, cdecl.}
proc psa_set_key_bits*(attributes: ptr psa_key_attributes_t; bits: uint) {.
    importc, cdecl.}
proc psa_get_key_bits*(attributes: ptr psa_key_attributes_t): uint {.importc,
    cdecl.}
proc psa_sign_hash_interruptible_operation_init*(): psa_sign_hash_interruptible_operation_s {.
    importc, cdecl.}
proc psa_verify_hash_interruptible_operation_init*(): psa_verify_hash_interruptible_operation_s {.
    importc, cdecl.}
{.pop.}
