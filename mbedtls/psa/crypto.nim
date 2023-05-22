import "crypto_types"
import "crypto_struct"
import "../pk"
import "../ecp"
import "../ecdh"
import "../cmac"
import "../utils"

{.compile: "./mbedtls/csources/library/psa_crypto.c".}
{.compile: "./mbedtls/csources/library/psa_crypto_hash.c".}
{.compile: "./mbedtls/csources/library/psa_crypto_slot_management.c".}
{.compile: "./mbedtls/csources/library/psa_crypto_storage.c".}
{.compile: "./mbedtls/csources/library/psa_its_file.c".}
{.compile: "./mbedtls/csources/library/psa_crypto_driver_wrappers.c".}
{.compile: "./mbedtls/csources/library/psa_crypto_pake.c".}
{.compile: "./mbedtls/csources/library/psa_crypto_rsa.c".}
{.compile: "./mbedtls/csources/library/psa_crypto_mac.c".}
{.compile: "./mbedtls/csources/library/psa_crypto_ecp.c".}
{.compile: "./mbedtls/csources/library/psa_crypto_aead.c".}
{.compile: "./mbedtls/csources/library/psa_crypto_cipher.c".}
{.compile: "./mbedtls/csources/library/psa_crypto_ffdh.c".}

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.pragma: impcryptoHdr, header: "/home/lchenut/minnim/webrtc/mbedtls/include/psa/crypto.h".}
{.pragma: impcrypto_compatHdr, header: "/home/lchenut/minnim/webrtc/mbedtls/include/psa/crypto_compat.h".}
{.pragma: impcrypto_extraHdr, header: "/home/lchenut/minnim/webrtc/mbedtls/include/psa/crypto_extra.h".}

{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/csources/include".}
{.passc: "-I./mbedtls/csources/library".}

defineEnum(psa_jpake_step)
defineEnum(psa_jpake_state)
defineEnum(psa_jpake_sequence)
defineEnum(psa_crypto_driver_pake_step)

const
  PSA_CRYPTO_API_VERSION_MAJOR* = 1
  PSA_CRYPTO_API_VERSION_MINOR* = 0
  PSA_KEY_DERIVATION_UNLIMITED_CAPACITY* = (cast[uint]((-1)))

  PSA_CRYPTO_ITS_RANDOM_SEED_UID* = 0xFFFFFF52
  MBEDTLS_PSA_KEY_SLOT_COUNT* = 32
  PSA_KEY_TYPE_DSA_PUBLIC_KEY* = (cast[psa_key_type_t](0x00004002))
  PSA_KEY_TYPE_DSA_KEY_PAIR* = (cast[psa_key_type_t](0x00007002))
  PSA_ALG_DSA_BASE* = (cast[psa_algorithm_t](0x06000400))
  PSA_ALG_DETERMINISTIC_DSA_BASE* = (cast[psa_algorithm_t](0x06000500))
  PSA_DH_FAMILY_CUSTOM* = (cast[psa_dh_family_t](0x0000007E))
  PSA_PAKE_OPERATION_STAGE_SETUP* = 0
  PSA_PAKE_OPERATION_STAGE_COLLECT_INPUTS* = 1
  PSA_PAKE_OPERATION_STAGE_COMPUTATION* = 2
  MBEDTLS_PSA_KEY_ID_BUILTIN_MIN* = (cast[psa_key_id_t](0x7FFF0000))
  MBEDTLS_PSA_KEY_ID_BUILTIN_MAX* = (cast[psa_key_id_t](0x7FFFEFFF))
  PSA_ALG_CATEGORY_PAKE* = (cast[psa_algorithm_t](0x0A000000))
  PSA_ALG_JPAKE* = (cast[psa_algorithm_t](0x0A000100))
  PSA_PAKE_ROLE_NONE* = (cast[psa_pake_role_t](0x00000000))
  PSA_PAKE_ROLE_FIRST* = (cast[psa_pake_role_t](0x00000001))
  PSA_PAKE_ROLE_SECOND* = (cast[psa_pake_role_t](0x00000002))
  PSA_PAKE_ROLE_CLIENT* = (cast[psa_pake_role_t](0x00000011))
  PSA_PAKE_ROLE_SERVER* = (cast[psa_pake_role_t](0x00000012))
  PSA_PAKE_PRIMITIVE_TYPE_ECC* = (cast[psa_pake_primitive_type_t](0x00000001))
  PSA_PAKE_PRIMITIVE_TYPE_DH* = (cast[psa_pake_primitive_type_t](0x00000002))
  PSA_PAKE_STEP_KEY_SHARE* = (cast[psa_pake_step_t](0x00000001))
  PSA_PAKE_STEP_ZK_PUBLIC* = (cast[psa_pake_step_t](0x00000002))
  PSA_PAKE_STEP_ZK_PROOF* = (cast[psa_pake_step_t](0x00000003))
  PSA_PAKE_OUTPUT_MAX_SIZE* = 65
  PSA_PAKE_INPUT_MAX_SIZE* = 65
  PSA_PAKE_STEP_INVALID* = (0).psa_jpake_step
  PSA_PAKE_STEP_X1_X2* = (1).psa_jpake_step
  PSA_PAKE_STEP_X2S* = (2).psa_jpake_step
  PSA_PAKE_STEP_DERIVE* = (3).psa_jpake_step
  PSA_PAKE_STATE_INVALID* = (0).psa_jpake_state
  PSA_PAKE_STATE_SETUP* = (1).psa_jpake_state
  PSA_PAKE_STATE_READY* = (2).psa_jpake_state
  PSA_PAKE_OUTPUT_X1_X2* = (3).psa_jpake_state
  PSA_PAKE_OUTPUT_X2S* = (4).psa_jpake_state
  PSA_PAKE_INPUT_X1_X2* = (5).psa_jpake_state
  PSA_PAKE_INPUT_X4S* = (6).psa_jpake_state
  PSA_PAKE_SEQ_INVALID* = (0).psa_jpake_sequence
  PSA_PAKE_X1_STEP_KEY_SHARE* = (1).psa_jpake_sequence
  PSA_PAKE_X1_STEP_ZK_PUBLIC* = (2).psa_jpake_sequence
  PSA_PAKE_X1_STEP_ZK_PROOF* = (3).psa_jpake_sequence
  PSA_PAKE_X2_STEP_KEY_SHARE* = (4).psa_jpake_sequence
  PSA_PAKE_X2_STEP_ZK_PUBLIC* = (5).psa_jpake_sequence
  PSA_PAKE_X2_STEP_ZK_PROOF* = (6).psa_jpake_sequence
  PSA_PAKE_SEQ_END* = (7).psa_jpake_sequence
  PSA_JPAKE_STEP_INVALID* = (0).psa_crypto_driver_pake_step
  PSA_JPAKE_X1_STEP_KEY_SHARE* = (1).psa_crypto_driver_pake_step
  PSA_JPAKE_X1_STEP_ZK_PUBLIC* = (2).psa_crypto_driver_pake_step
  PSA_JPAKE_X1_STEP_ZK_PROOF* = (3).psa_crypto_driver_pake_step
  PSA_JPAKE_X2_STEP_KEY_SHARE* = (4).psa_crypto_driver_pake_step
  PSA_JPAKE_X2_STEP_ZK_PUBLIC* = (5).psa_crypto_driver_pake_step
  PSA_JPAKE_X2_STEP_ZK_PROOF* = (6).psa_crypto_driver_pake_step
  PSA_JPAKE_X2S_STEP_KEY_SHARE* = (7).psa_crypto_driver_pake_step
  PSA_JPAKE_X2S_STEP_ZK_PUBLIC* = (8).psa_crypto_driver_pake_step
  PSA_JPAKE_X2S_STEP_ZK_PROOF* = (9).psa_crypto_driver_pake_step
  PSA_JPAKE_X4S_STEP_KEY_SHARE* = (10).psa_crypto_driver_pake_step
  PSA_JPAKE_X4S_STEP_ZK_PUBLIC* = (11).psa_crypto_driver_pake_step
  PSA_JPAKE_X4S_STEP_ZK_PROOF* = (12).psa_crypto_driver_pake_step

type
  psa_hash_operation_t* {.importc, impcryptoHdr.} = psa_hash_operation_s
  psa_mac_operation_t* {.importc, impcryptoHdr.} = psa_mac_operation_s
  psa_cipher_operation_t* {.importc, impcryptoHdr.} = psa_cipher_operation_s
  psa_aead_operation_t* {.importc, impcryptoHdr.} = psa_aead_operation_s
  psa_key_derivation_operation_t* {.importc, impcryptoHdr.} = psa_key_derivation_s
  psa_sign_hash_interruptible_operation_t* {.importc, impcryptoHdr.} = psa_sign_hash_interruptible_operation_s
  psa_verify_hash_interruptible_operation_t* {.importc, impcryptoHdr.} = psa_verify_hash_interruptible_operation_s

  psa_key_handle_t* {.importc, impcrypto_compatHdr.} = mbedtls_svc_key_id_t

  mbedtls_psa_stats_s* {.bycopy, impcrypto_extraHdr,
                         importc: "struct mbedtls_psa_stats_s".} = object
    private_volatile_slots*: uint
    private_persistent_slots*: uint
    private_external_slots*: uint
    private_half_filled_slots*: uint
    private_cache_slots*: uint
    private_empty_slots*: uint
    private_locked_slots*: uint
    private_max_open_internal_key_id*: psa_key_id_t
    private_max_open_external_key_id*: psa_key_id_t

  mbedtls_psa_stats_t* {.importc, impcrypto_extraHdr.} = mbedtls_psa_stats_s
  psa_drv_slot_number_t* {.importc, impcrypto_extraHdr.} = uint64
  psa_pake_role_t* {.importc, impcrypto_extraHdr.} = uint8
  psa_pake_step_t* {.importc, impcrypto_extraHdr.} = uint8
  psa_pake_primitive_type_t* {.importc, impcrypto_extraHdr.} = uint8
  psa_pake_family_t* {.importc, impcrypto_extraHdr.} = uint8
  psa_pake_primitive_t* {.importc, impcrypto_extraHdr.} = uint32
  psa_pake_cipher_suite_t* {.importc, impcrypto_extraHdr.} = psa_pake_cipher_suite_s
  psa_pake_operation_t* {.importc, impcrypto_extraHdr.} = psa_pake_operation_s
  psa_crypto_driver_pake_inputs_t* {.importc, impcrypto_extraHdr.} = psa_crypto_driver_pake_inputs_s
  psa_jpake_computation_stage_t* {.importc, impcrypto_extraHdr.} = psa_jpake_computation_stage_s
  psa_pake_cipher_suite_s* {.bycopy, impcrypto_extraHdr,
                             importc: "struct psa_pake_cipher_suite_s".} = object
    algorithm*: psa_algorithm_t
    `type`*: psa_pake_primitive_type_t
    family*: psa_pake_family_t
    bits*: uint16
    hash*: psa_algorithm_t

  psa_crypto_driver_pake_inputs_s* {.bycopy, impcrypto_extraHdr, importc: "struct psa_crypto_driver_pake_inputs_s".} = object
    private_password*: ptr uint8
    private_password_len*: uint
    private_role*: psa_pake_role_t
    private_user*: ptr uint8
    private_user_len*: uint
    private_peer*: ptr uint8
    private_peer_len*: uint
    private_attributes*: psa_key_attributes_t
    private_cipher_suite*: psa_pake_cipher_suite_t

  psa_jpake_step_t* {.importc, impcrypto_extraHdr.} = psa_jpake_step
  psa_jpake_state_t* {.importc, impcrypto_extraHdr.} = psa_jpake_state
  psa_jpake_sequence_t* {.importc, impcrypto_extraHdr.} = psa_jpake_sequence
  psa_crypto_driver_pake_step_t* {.importc, impcrypto_extraHdr.} = psa_crypto_driver_pake_step
  psa_jpake_computation_stage_s* {.bycopy, impcrypto_extraHdr, importc: "struct psa_jpake_computation_stage_s".} = object
    private_state*: psa_jpake_state_t
    private_sequence*: psa_jpake_sequence_t
    private_input_step*: psa_jpake_step_t
    private_output_step*: psa_jpake_step_t

  Union_crypto_extrah1* {.union, bycopy, impcrypto_extraHdr,
                          importc: "union Union_crypto_extrah1".} = object
    private_dummy*: uint8
    private_jpake*: psa_jpake_computation_stage_t

  Union_crypto_extrah2* {.union, bycopy, impcrypto_extraHdr,
                          importc: "union Union_crypto_extrah2".} = object
    private_ctx*: psa_driver_pake_context_t
    private_inputs*: psa_crypto_driver_pake_inputs_t

  psa_pake_operation_s* {.bycopy, impcrypto_extraHdr,
                          importc: "struct psa_pake_operation_s".} = object
    private_id*: cuint
    private_alg*: psa_algorithm_t
    private_primitive*: psa_pake_primitive_t
    private_stage*: uint8
    private_computation_stage*: Union_crypto_extrah1
    private_data*: Union_crypto_extrah2

proc psa_crypto_init*(): psa_status_t {.importc, cdecl, impcryptoHdr.}
proc psa_key_attributes_init*(): psa_key_attributes_t {.importc, cdecl,
    impcryptoHdr.}
proc psa_set_key_id*(attributes: ptr psa_key_attributes_t;
                     key: mbedtls_svc_key_id_t) {.importc, cdecl, impcryptoHdr.}
proc psa_set_key_lifetime*(attributes: ptr psa_key_attributes_t;
                           lifetime: psa_key_lifetime_t) {.importc, cdecl,
    impcryptoHdr.}
proc psa_get_key_id*(attributes: ptr psa_key_attributes_t): mbedtls_svc_key_id_t {.
    importc, cdecl, impcryptoHdr.}
proc psa_get_key_lifetime*(attributes: ptr psa_key_attributes_t): psa_key_lifetime_t {.
    importc, cdecl, impcryptoHdr.}
proc psa_set_key_usage_flags*(attributes: ptr psa_key_attributes_t;
                              usage_flags: psa_key_usage_t) {.importc, cdecl,
    impcryptoHdr.}
proc psa_get_key_usage_flags*(attributes: ptr psa_key_attributes_t): psa_key_usage_t {.
    importc, cdecl, impcryptoHdr.}
proc psa_set_key_algorithm*(attributes: ptr psa_key_attributes_t;
                            alg: psa_algorithm_t) {.importc, cdecl, impcryptoHdr.}
proc psa_get_key_algorithm*(attributes: ptr psa_key_attributes_t): psa_algorithm_t {.
    importc, cdecl, impcryptoHdr.}
proc psa_set_key_type*(attributes: ptr psa_key_attributes_t;
                       `type`: psa_key_type_t) {.importc, cdecl, impcryptoHdr.}
proc psa_set_key_bits*(attributes: ptr psa_key_attributes_t; bits: uint) {.
    importc, cdecl, impcryptoHdr.}
proc psa_get_key_type*(attributes: ptr psa_key_attributes_t): psa_key_type_t {.
    importc, cdecl, impcryptoHdr.}
proc psa_get_key_bits*(attributes: ptr psa_key_attributes_t): uint {.importc,
    cdecl, impcryptoHdr.}
proc psa_get_key_attributes*(key: mbedtls_svc_key_id_t;
                             attributes: ptr psa_key_attributes_t): psa_status_t {.
    importc, cdecl, impcryptoHdr.}
proc psa_reset_key_attributes*(attributes: ptr psa_key_attributes_t) {.importc,
    cdecl, impcryptoHdr.}
proc psa_purge_key*(key: mbedtls_svc_key_id_t): psa_status_t {.importc, cdecl,
    impcryptoHdr.}
proc psa_copy_key*(source_key: mbedtls_svc_key_id_t;
                   attributes: ptr psa_key_attributes_t;
                   target_key: ptr mbedtls_svc_key_id_t): psa_status_t {.
    importc, cdecl, impcryptoHdr.}
proc psa_destroy_key*(key: mbedtls_svc_key_id_t): psa_status_t {.importc, cdecl,
    impcryptoHdr.}
proc psa_import_key*(attributes: ptr psa_key_attributes_t; data: ptr uint8;
                     data_length: uint; key: ptr mbedtls_svc_key_id_t): psa_status_t {.
    importc, cdecl, impcryptoHdr.}
proc psa_export_key*(key: mbedtls_svc_key_id_t; data: ptr uint8;
                     data_size: uint; data_length: ptr uint): psa_status_t {.
    importc, cdecl, impcryptoHdr.}
proc psa_export_public_key*(key: mbedtls_svc_key_id_t; data: ptr uint8;
                            data_size: uint; data_length: ptr uint): psa_status_t {.
    importc, cdecl, impcryptoHdr.}
proc psa_hash_compute*(alg: psa_algorithm_t; input: ptr uint8;
                       input_length: uint; hash: ptr uint8; hash_size: uint;
                       hash_length: ptr uint): psa_status_t {.importc, cdecl,
    impcryptoHdr.}
proc psa_hash_compare*(alg: psa_algorithm_t; input: ptr uint8;
                       input_length: uint; hash: ptr uint8; hash_length: uint): psa_status_t {.
    importc, cdecl, impcryptoHdr.}
proc psa_hash_operation_init*(): psa_hash_operation_t {.importc, cdecl,
    impcryptoHdr.}
proc psa_hash_setup*(operation: ptr psa_hash_operation_t; alg: psa_algorithm_t): psa_status_t {.
    importc, cdecl, impcryptoHdr.}
proc psa_hash_update*(operation: ptr psa_hash_operation_t; input: ptr uint8;
                      input_length: uint): psa_status_t {.importc, cdecl,
    impcryptoHdr.}
proc psa_hash_finish*(operation: ptr psa_hash_operation_t; hash: ptr uint8;
                      hash_size: uint; hash_length: ptr uint): psa_status_t {.
    importc, cdecl, impcryptoHdr.}
proc psa_hash_verify*(operation: ptr psa_hash_operation_t; hash: ptr uint8;
                      hash_length: uint): psa_status_t {.importc, cdecl,
    impcryptoHdr.}
proc psa_hash_abort*(operation: ptr psa_hash_operation_t): psa_status_t {.
    importc, cdecl, impcryptoHdr.}
proc psa_hash_clone*(source_operation: ptr psa_hash_operation_t;
                     target_operation: ptr psa_hash_operation_t): psa_status_t {.
    importc, cdecl, impcryptoHdr.}
proc psa_mac_compute*(key: mbedtls_svc_key_id_t; alg: psa_algorithm_t;
                      input: ptr uint8; input_length: uint; mac: ptr uint8;
                      mac_size: uint; mac_length: ptr uint): psa_status_t {.
    importc, cdecl, impcryptoHdr.}
proc psa_mac_verify*(key: mbedtls_svc_key_id_t; alg: psa_algorithm_t;
                     input: ptr uint8; input_length: uint; mac: ptr uint8;
                     mac_length: uint): psa_status_t {.importc, cdecl,
    impcryptoHdr.}
proc psa_mac_operation_init*(): psa_mac_operation_t {.importc, cdecl,
    impcryptoHdr.}
proc psa_mac_sign_setup*(operation: ptr psa_mac_operation_t;
                         key: mbedtls_svc_key_id_t; alg: psa_algorithm_t): psa_status_t {.
    importc, cdecl, impcryptoHdr.}
proc psa_mac_verify_setup*(operation: ptr psa_mac_operation_t;
                           key: mbedtls_svc_key_id_t; alg: psa_algorithm_t): psa_status_t {.
    importc, cdecl, impcryptoHdr.}
proc psa_mac_update*(operation: ptr psa_mac_operation_t; input: ptr uint8;
                     input_length: uint): psa_status_t {.importc, cdecl,
    impcryptoHdr.}
proc psa_mac_sign_finish*(operation: ptr psa_mac_operation_t; mac: ptr uint8;
                          mac_size: uint; mac_length: ptr uint): psa_status_t {.
    importc, cdecl, impcryptoHdr.}
proc psa_mac_verify_finish*(operation: ptr psa_mac_operation_t; mac: ptr uint8;
                            mac_length: uint): psa_status_t {.importc, cdecl,
    impcryptoHdr.}
proc psa_mac_abort*(operation: ptr psa_mac_operation_t): psa_status_t {.importc,
    cdecl, impcryptoHdr.}
proc psa_cipher_encrypt*(key: mbedtls_svc_key_id_t; alg: psa_algorithm_t;
                         input: ptr uint8; input_length: uint;
                         output: ptr uint8; output_size: uint;
                         output_length: ptr uint): psa_status_t {.importc,
    cdecl, impcryptoHdr.}
proc psa_cipher_decrypt*(key: mbedtls_svc_key_id_t; alg: psa_algorithm_t;
                         input: ptr uint8; input_length: uint;
                         output: ptr uint8; output_size: uint;
                         output_length: ptr uint): psa_status_t {.importc,
    cdecl, impcryptoHdr.}
proc psa_cipher_operation_init*(): psa_cipher_operation_t {.importc, cdecl,
    impcryptoHdr.}
proc psa_cipher_encrypt_setup*(operation: ptr psa_cipher_operation_t;
                               key: mbedtls_svc_key_id_t; alg: psa_algorithm_t): psa_status_t {.
    importc, cdecl, impcryptoHdr.}
proc psa_cipher_decrypt_setup*(operation: ptr psa_cipher_operation_t;
                               key: mbedtls_svc_key_id_t; alg: psa_algorithm_t): psa_status_t {.
    importc, cdecl, impcryptoHdr.}
proc psa_cipher_generate_iv*(operation: ptr psa_cipher_operation_t;
                             iv: ptr uint8; iv_size: uint; iv_length: ptr uint): psa_status_t {.
    importc, cdecl, impcryptoHdr.}
proc psa_cipher_set_iv*(operation: ptr psa_cipher_operation_t; iv: ptr uint8;
                        iv_length: uint): psa_status_t {.importc, cdecl,
    impcryptoHdr.}
proc psa_cipher_update*(operation: ptr psa_cipher_operation_t; input: ptr uint8;
                        input_length: uint; output: ptr uint8;
                        output_size: uint; output_length: ptr uint): psa_status_t {.
    importc, cdecl, impcryptoHdr.}
proc psa_cipher_finish*(operation: ptr psa_cipher_operation_t;
                        output: ptr uint8; output_size: uint;
                        output_length: ptr uint): psa_status_t {.importc, cdecl,
    impcryptoHdr.}
proc psa_cipher_abort*(operation: ptr psa_cipher_operation_t): psa_status_t {.
    importc, cdecl, impcryptoHdr.}
proc psa_aead_encrypt*(key: mbedtls_svc_key_id_t; alg: psa_algorithm_t;
                       nonce: ptr uint8; nonce_length: uint;
                       additional_data: ptr uint8; additional_data_length: uint;
                       plaintext: ptr uint8; plaintext_length: uint;
                       ciphertext: ptr uint8; ciphertext_size: uint;
                       ciphertext_length: ptr uint): psa_status_t {.importc,
    cdecl, impcryptoHdr.}
proc psa_aead_decrypt*(key: mbedtls_svc_key_id_t; alg: psa_algorithm_t;
                       nonce: ptr uint8; nonce_length: uint;
                       additional_data: ptr uint8; additional_data_length: uint;
                       ciphertext: ptr uint8; ciphertext_length: uint;
                       plaintext: ptr uint8; plaintext_size: uint;
                       plaintext_length: ptr uint): psa_status_t {.importc,
    cdecl, impcryptoHdr.}
proc psa_aead_operation_init*(): psa_aead_operation_t {.importc, cdecl,
    impcryptoHdr.}
proc psa_aead_encrypt_setup*(operation: ptr psa_aead_operation_t;
                             key: mbedtls_svc_key_id_t; alg: psa_algorithm_t): psa_status_t {.
    importc, cdecl, impcryptoHdr.}
proc psa_aead_decrypt_setup*(operation: ptr psa_aead_operation_t;
                             key: mbedtls_svc_key_id_t; alg: psa_algorithm_t): psa_status_t {.
    importc, cdecl, impcryptoHdr.}
proc psa_aead_generate_nonce*(operation: ptr psa_aead_operation_t;
                              nonce: ptr uint8; nonce_size: uint;
                              nonce_length: ptr uint): psa_status_t {.importc,
    cdecl, impcryptoHdr.}
proc psa_aead_set_nonce*(operation: ptr psa_aead_operation_t; nonce: ptr uint8;
                         nonce_length: uint): psa_status_t {.importc, cdecl,
    impcryptoHdr.}
proc psa_aead_set_lengths*(operation: ptr psa_aead_operation_t; ad_length: uint;
                           plaintext_length: uint): psa_status_t {.importc,
    cdecl, impcryptoHdr.}
proc psa_aead_update_ad*(operation: ptr psa_aead_operation_t; input: ptr uint8;
                         input_length: uint): psa_status_t {.importc, cdecl,
    impcryptoHdr.}
proc psa_aead_update*(operation: ptr psa_aead_operation_t; input: ptr uint8;
                      input_length: uint; output: ptr uint8; output_size: uint;
                      output_length: ptr uint): psa_status_t {.importc, cdecl,
    impcryptoHdr.}
proc psa_aead_finish*(operation: ptr psa_aead_operation_t;
                      ciphertext: ptr uint8; ciphertext_size: uint;
                      ciphertext_length: ptr uint; tag: ptr uint8;
                      tag_size: uint; tag_length: ptr uint): psa_status_t {.
    importc, cdecl, impcryptoHdr.}
proc psa_aead_verify*(operation: ptr psa_aead_operation_t; plaintext: ptr uint8;
                      plaintext_size: uint; plaintext_length: ptr uint;
                      tag: ptr uint8; tag_length: uint): psa_status_t {.importc,
    cdecl, impcryptoHdr.}
proc psa_aead_abort*(operation: ptr psa_aead_operation_t): psa_status_t {.
    importc, cdecl, impcryptoHdr.}
proc psa_sign_message*(key: mbedtls_svc_key_id_t; alg: psa_algorithm_t;
                       input: ptr uint8; input_length: uint;
                       signature: ptr uint8; signature_size: uint;
                       signature_length: ptr uint): psa_status_t {.importc,
    cdecl, impcryptoHdr.}
proc psa_verify_message*(key: mbedtls_svc_key_id_t; alg: psa_algorithm_t;
                         input: ptr uint8; input_length: uint;
                         signature: ptr uint8; signature_length: uint): psa_status_t {.
    importc, cdecl, impcryptoHdr.}
proc psa_sign_hash*(key: mbedtls_svc_key_id_t; alg: psa_algorithm_t;
                    hash: ptr uint8; hash_length: uint; signature: ptr uint8;
                    signature_size: uint; signature_length: ptr uint): psa_status_t {.
    importc, cdecl, impcryptoHdr.}
proc psa_verify_hash*(key: mbedtls_svc_key_id_t; alg: psa_algorithm_t;
                      hash: ptr uint8; hash_length: uint; signature: ptr uint8;
                      signature_length: uint): psa_status_t {.importc, cdecl,
    impcryptoHdr.}
proc psa_asymmetric_encrypt*(key: mbedtls_svc_key_id_t; alg: psa_algorithm_t;
                             input: ptr uint8; input_length: uint;
                             salt: ptr uint8; salt_length: uint;
                             output: ptr uint8; output_size: uint;
                             output_length: ptr uint): psa_status_t {.importc,
    cdecl, impcryptoHdr.}
proc psa_asymmetric_decrypt*(key: mbedtls_svc_key_id_t; alg: psa_algorithm_t;
                             input: ptr uint8; input_length: uint;
                             salt: ptr uint8; salt_length: uint;
                             output: ptr uint8; output_size: uint;
                             output_length: ptr uint): psa_status_t {.importc,
    cdecl, impcryptoHdr.}
proc psa_key_derivation_operation_init*(): psa_key_derivation_operation_t {.
    importc, cdecl, impcryptoHdr.}
proc psa_key_derivation_setup*(operation: ptr psa_key_derivation_operation_t;
                               alg: psa_algorithm_t): psa_status_t {.importc,
    cdecl, impcryptoHdr.}
proc psa_key_derivation_get_capacity*(operation: ptr psa_key_derivation_operation_t;
                                      capacity: ptr uint): psa_status_t {.
    importc, cdecl, impcryptoHdr.}
proc psa_key_derivation_set_capacity*(operation: ptr psa_key_derivation_operation_t;
                                      capacity: uint): psa_status_t {.importc,
    cdecl, impcryptoHdr.}
proc psa_key_derivation_input_bytes*(operation: ptr psa_key_derivation_operation_t;
                                     step: psa_key_derivation_step_t;
                                     data: ptr uint8; data_length: uint): psa_status_t {.
    importc, cdecl, impcryptoHdr.}
proc psa_key_derivation_input_integer*(operation: ptr psa_key_derivation_operation_t;
                                       step: psa_key_derivation_step_t;
                                       value: uint64): psa_status_t {.importc,
    cdecl, impcryptoHdr.}
proc psa_key_derivation_input_key*(operation: ptr psa_key_derivation_operation_t;
                                   step: psa_key_derivation_step_t;
                                   key: mbedtls_svc_key_id_t): psa_status_t {.
    importc, cdecl, impcryptoHdr.}
proc psa_key_derivation_key_agreement*(operation: ptr psa_key_derivation_operation_t;
                                       step: psa_key_derivation_step_t;
                                       private_key: mbedtls_svc_key_id_t;
                                       peer_key: ptr uint8;
                                       peer_key_length: uint): psa_status_t {.
    importc, cdecl, impcryptoHdr.}
proc psa_key_derivation_output_bytes*(operation: ptr psa_key_derivation_operation_t;
                                      output: ptr uint8; output_length: uint): psa_status_t {.
    importc, cdecl, impcryptoHdr.}
proc psa_key_derivation_output_key*(attributes: ptr psa_key_attributes_t;
    operation: ptr psa_key_derivation_operation_t; key: ptr mbedtls_svc_key_id_t): psa_status_t {.
    importc, cdecl, impcryptoHdr.}
proc psa_key_derivation_verify_bytes*(operation: ptr psa_key_derivation_operation_t;
                                      expected_output: ptr uint8;
                                      output_length: uint): psa_status_t {.
    importc, cdecl, impcryptoHdr.}
proc psa_key_derivation_verify_key*(operation: ptr psa_key_derivation_operation_t;
                                    expected: psa_key_id_t): psa_status_t {.
    importc, cdecl, impcryptoHdr.}
proc psa_key_derivation_abort*(operation: ptr psa_key_derivation_operation_t): psa_status_t {.
    importc, cdecl, impcryptoHdr.}
proc psa_raw_key_agreement*(alg: psa_algorithm_t;
                            private_key: mbedtls_svc_key_id_t;
                            peer_key: ptr uint8; peer_key_length: uint;
                            output: ptr uint8; output_size: uint;
                            output_length: ptr uint): psa_status_t {.importc,
    cdecl, impcryptoHdr.}
proc psa_generate_random*(output: ptr uint8; output_size: uint): psa_status_t {.
    importc, cdecl, impcryptoHdr.}
proc psa_generate_key*(attributes: ptr psa_key_attributes_t;
                       key: ptr mbedtls_svc_key_id_t): psa_status_t {.importc,
    cdecl, impcryptoHdr.}
proc psa_interruptible_set_max_ops*(max_ops: uint32) {.importc, cdecl,
    impcryptoHdr.}
proc psa_interruptible_get_max_ops*(): uint32 {.importc, cdecl, impcryptoHdr.}
proc psa_sign_hash_get_num_ops*(operation: ptr psa_sign_hash_interruptible_operation_t): uint32 {.
    importc, cdecl, impcryptoHdr.}
proc psa_verify_hash_get_num_ops*(operation: ptr psa_verify_hash_interruptible_operation_t): uint32 {.
    importc, cdecl, impcryptoHdr.}
proc psa_sign_hash_start*(operation: ptr psa_sign_hash_interruptible_operation_t;
                          key: mbedtls_svc_key_id_t; alg: psa_algorithm_t;
                          hash: ptr uint8; hash_length: uint): psa_status_t {.
    importc, cdecl, impcryptoHdr.}
proc psa_sign_hash_complete*(operation: ptr psa_sign_hash_interruptible_operation_t;
                             signature: ptr uint8; signature_size: uint;
                             signature_length: ptr uint): psa_status_t {.
    importc, cdecl, impcryptoHdr.}
proc psa_sign_hash_abort*(operation: ptr psa_sign_hash_interruptible_operation_t): psa_status_t {.
    importc, cdecl, impcryptoHdr.}
proc psa_verify_hash_start*(operation: ptr psa_verify_hash_interruptible_operation_t;
                            key: mbedtls_svc_key_id_t; alg: psa_algorithm_t;
                            hash: ptr uint8; hash_length: uint;
                            signature: ptr uint8; signature_length: uint): psa_status_t {.
    importc, cdecl, impcryptoHdr.}
proc psa_verify_hash_complete*(operation: ptr psa_verify_hash_interruptible_operation_t): psa_status_t {.
    importc, cdecl, impcryptoHdr.}
proc psa_verify_hash_abort*(operation: ptr psa_verify_hash_interruptible_operation_t): psa_status_t {.
    importc, cdecl, impcryptoHdr.}

proc psa_key_handle_is_null*(handle: psa_key_handle_t): cint {.importc, cdecl,
    impcrypto_compatHdr.}
proc psa_open_key*(key: mbedtls_svc_key_id_t; handle: ptr psa_key_handle_t): psa_status_t {.
    importc, cdecl, impcrypto_compatHdr.}
proc psa_close_key*(handle: psa_key_handle_t): psa_status_t {.importc, cdecl,
    impcrypto_compatHdr.}

proc psa_set_key_enrollment_algorithm*(attributes: ptr psa_key_attributes_t;
                                       alg2: psa_algorithm_t) {.importc, cdecl,
    impcrypto_extraHdr.}
proc psa_get_key_enrollment_algorithm*(attributes: ptr psa_key_attributes_t): psa_algorithm_t {.
    importc, cdecl, impcrypto_extraHdr.}
proc mbedtls_psa_crypto_free*() {.importc, cdecl, impcrypto_extraHdr.}
proc mbedtls_psa_get_stats*(stats: ptr mbedtls_psa_stats_t) {.importc, cdecl,
    impcrypto_extraHdr.}
proc mbedtls_psa_inject_entropy*(seed: ptr uint8; seed_size: uint): psa_status_t {.
    importc, cdecl, impcrypto_extraHdr.}
proc psa_set_key_domain_parameters*(attributes: ptr psa_key_attributes_t;
                                    `type`: psa_key_type_t; data: ptr uint8;
                                    data_length: uint): psa_status_t {.importc,
    cdecl, impcrypto_extraHdr.}
proc psa_get_key_domain_parameters*(attributes: ptr psa_key_attributes_t;
                                    data: ptr uint8; data_size: uint;
                                    data_length: ptr uint): psa_status_t {.
    importc, cdecl, impcrypto_extraHdr.}
proc mbedtls_ecc_group_to_psa*(grpid: mbedtls_ecp_group_id; bits: ptr uint): psa_ecc_family_t {.
    importc, cdecl, impcrypto_extraHdr.}
proc mbedtls_ecc_group_of_psa*(curve: psa_ecc_family_t; bits: uint;
                               bits_is_sloppy: cint): mbedtls_ecp_group_id {.
    importc, cdecl, impcrypto_extraHdr.}
proc psa_pake_cipher_suite_init*(): psa_pake_cipher_suite_t {.importc, cdecl,
    impcrypto_extraHdr.}
proc psa_pake_cs_get_algorithm*(cipher_suite: ptr psa_pake_cipher_suite_t): psa_algorithm_t {.
    importc, cdecl, impcrypto_extraHdr.}
proc psa_pake_cs_set_algorithm*(cipher_suite: ptr psa_pake_cipher_suite_t;
                                algorithm: psa_algorithm_t) {.importc, cdecl,
    impcrypto_extraHdr.}
proc psa_pake_cs_get_primitive*(cipher_suite: ptr psa_pake_cipher_suite_t): psa_pake_primitive_t {.
    importc, cdecl, impcrypto_extraHdr.}
proc psa_pake_cs_set_primitive*(cipher_suite: ptr psa_pake_cipher_suite_t;
                                primitive: psa_pake_primitive_t) {.importc,
    cdecl, impcrypto_extraHdr.}
proc psa_pake_cs_get_family*(cipher_suite: ptr psa_pake_cipher_suite_t): psa_pake_family_t {.
    importc, cdecl, impcrypto_extraHdr.}
proc psa_pake_cs_get_bits*(cipher_suite: ptr psa_pake_cipher_suite_t): uint16 {.
    importc, cdecl, impcrypto_extraHdr.}
proc psa_pake_cs_get_hash*(cipher_suite: ptr psa_pake_cipher_suite_t): psa_algorithm_t {.
    importc, cdecl, impcrypto_extraHdr.}
proc psa_pake_cs_set_hash*(cipher_suite: ptr psa_pake_cipher_suite_t;
                           hash: psa_algorithm_t) {.importc, cdecl,
    impcrypto_extraHdr.}
proc psa_pake_operation_init*(): psa_pake_operation_t {.importc, cdecl,
    impcrypto_extraHdr.}
proc psa_crypto_driver_pake_get_password_len*(
    inputs: ptr psa_crypto_driver_pake_inputs_t; password_len: ptr uint): psa_status_t {.
    importc, cdecl, impcrypto_extraHdr.}
proc psa_crypto_driver_pake_get_password*(
    inputs: ptr psa_crypto_driver_pake_inputs_t; buffer: ptr uint8;
    buffer_size: uint; buffer_length: ptr uint): psa_status_t {.importc, cdecl,
    impcrypto_extraHdr.}
proc psa_crypto_driver_pake_get_role*(inputs: ptr psa_crypto_driver_pake_inputs_t;
                                      role: ptr psa_pake_role_t): psa_status_t {.
    importc, cdecl, impcrypto_extraHdr.}
proc psa_crypto_driver_pake_get_user_len*(
    inputs: ptr psa_crypto_driver_pake_inputs_t; user_len: ptr uint): psa_status_t {.
    importc, cdecl, impcrypto_extraHdr.}
proc psa_crypto_driver_pake_get_peer_len*(
    inputs: ptr psa_crypto_driver_pake_inputs_t; peer_len: ptr uint): psa_status_t {.
    importc, cdecl, impcrypto_extraHdr.}
proc psa_crypto_driver_pake_get_user*(inputs: ptr psa_crypto_driver_pake_inputs_t;
                                      user_id: ptr uint8; user_id_size: uint;
                                      user_id_len: ptr uint): psa_status_t {.
    importc, cdecl, impcrypto_extraHdr.}
proc psa_crypto_driver_pake_get_peer*(inputs: ptr psa_crypto_driver_pake_inputs_t;
                                      peer_id: ptr uint8; peer_id_size: uint;
                                      peer_id_length: ptr uint): psa_status_t {.
    importc, cdecl, impcrypto_extraHdr.}
proc psa_crypto_driver_pake_get_cipher_suite*(
    inputs: ptr psa_crypto_driver_pake_inputs_t;
    cipher_suite: ptr psa_pake_cipher_suite_t): psa_status_t {.importc, cdecl,
    impcrypto_extraHdr.}
proc psa_pake_setup*(operation: ptr psa_pake_operation_t;
                     cipher_suite: ptr psa_pake_cipher_suite_t): psa_status_t {.
    importc, cdecl, impcrypto_extraHdr.}
proc psa_pake_set_password_key*(operation: ptr psa_pake_operation_t;
                                password: mbedtls_svc_key_id_t): psa_status_t {.
    importc, cdecl, impcrypto_extraHdr.}
proc psa_pake_set_user*(operation: ptr psa_pake_operation_t; user_id: ptr uint8;
                        user_id_len: uint): psa_status_t {.importc, cdecl,
    impcrypto_extraHdr.}
proc psa_pake_set_peer*(operation: ptr psa_pake_operation_t; peer_id: ptr uint8;
                        peer_id_len: uint): psa_status_t {.importc, cdecl,
    impcrypto_extraHdr.}
proc psa_pake_set_role*(operation: ptr psa_pake_operation_t;
                        role: psa_pake_role_t): psa_status_t {.importc, cdecl,
    impcrypto_extraHdr.}
proc psa_pake_output*(operation: ptr psa_pake_operation_t;
                      step: psa_pake_step_t; output: ptr uint8;
                      output_size: uint; output_length: ptr uint): psa_status_t {.
    importc, cdecl, impcrypto_extraHdr.}
proc psa_pake_input*(operation: ptr psa_pake_operation_t; step: psa_pake_step_t;
                     input: ptr uint8; input_length: uint): psa_status_t {.
    importc, cdecl, impcrypto_extraHdr.}
proc psa_pake_get_implicit_key*(operation: ptr psa_pake_operation_t;
                                output: ptr psa_key_derivation_operation_t): psa_status_t {.
    importc, cdecl, impcrypto_extraHdr.}
proc psa_pake_abort*(operation: ptr psa_pake_operation_t): psa_status_t {.
    importc, cdecl, impcrypto_extraHdr.}
{.pop.}
