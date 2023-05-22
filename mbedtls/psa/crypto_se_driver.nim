import "crypto_driver_common"
import "crypto_types"
import "../utils"

{.compile: "./mbedtls/csources/library/psa_crypto_se.c".}

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.pragma: impcrypto_se_driverHdr,
  header: "/home/lchenut/minnim/webrtc/mbedtls/include/psa/crypto_se_driver.h".}
{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/csources/include".}
{.passc: "-I./mbedtls/csources/library".}

defineEnum(psa_key_creation_method_t)

const
  PSA_KEY_CREATION_IMPORT* = (0).psa_key_creation_method_t
  PSA_KEY_CREATION_GENERATE* = (PSA_KEY_CREATION_IMPORT + 1).psa_key_creation_method_t
  PSA_KEY_CREATION_DERIVE* = (PSA_KEY_CREATION_GENERATE + 1).psa_key_creation_method_t
  PSA_KEY_CREATION_COPY* = (PSA_KEY_CREATION_DERIVE + 1).psa_key_creation_method_t
  PSA_KEY_CREATION_REGISTER* = (PSA_KEY_CREATION_COPY + 1).psa_key_creation_method_t
  PSA_DRV_SE_HAL_VERSION* = 0x00000005
type
  psa_drv_se_context_t* {.bycopy, importc, impcrypto_se_driverHdr.} = object
    private_persistent_data*: pointer
    private_persistent_data_size*: uint
    private_transient_data*: ptr uint

  psa_drv_se_init_t* {.importc, impcrypto_se_driverHdr.} = proc (
      drv_context: ptr psa_drv_se_context_t; persistent_data: pointer;
      location: psa_key_location_t): psa_status_t {.cdecl.}
  psa_key_slot_number_t* {.importc, impcrypto_se_driverHdr.} = uint64
  psa_drv_se_mac_setup_t* {.importc, impcrypto_se_driverHdr.} = proc (
      drv_context: ptr psa_drv_se_context_t; op_context: pointer;
      key_slot: psa_key_slot_number_t; algorithm: psa_algorithm_t): psa_status_t {.
      cdecl.}
  psa_drv_se_mac_update_t* {.importc, impcrypto_se_driverHdr.} = proc (
      op_context: pointer; p_input: ptr uint8; input_length: uint): psa_status_t {.
      cdecl.}
  psa_drv_se_mac_finish_t* {.importc, impcrypto_se_driverHdr.} = proc (
      op_context: pointer; p_mac: ptr uint8; mac_size: uint;
      p_mac_length: ptr uint): psa_status_t {.cdecl.}
  psa_drv_se_mac_finish_verify_t* {.importc, impcrypto_se_driverHdr.} = proc (
      op_context: pointer; p_mac: ptr uint8; mac_length: uint): psa_status_t {.
      cdecl.}
  psa_drv_se_mac_abort_t* {.importc, impcrypto_se_driverHdr.} = proc (
      op_context: pointer): psa_status_t {.cdecl.}
  psa_drv_se_mac_generate_t* {.importc, impcrypto_se_driverHdr.} = proc (
      drv_context: ptr psa_drv_se_context_t; p_input: ptr uint8;
      input_length: uint; key_slot: psa_key_slot_number_t; alg: psa_algorithm_t;
      p_mac: ptr uint8; mac_size: uint; p_mac_length: ptr uint): psa_status_t {.
      cdecl.}
  psa_drv_se_mac_verify_t* {.importc, impcrypto_se_driverHdr.} = proc (
      drv_context: ptr psa_drv_se_context_t; p_input: ptr uint8;
      input_length: uint; key_slot: psa_key_slot_number_t; alg: psa_algorithm_t;
      p_mac: ptr uint8; mac_length: uint): psa_status_t {.cdecl.}
  psa_drv_se_mac_t* {.bycopy, importc, impcrypto_se_driverHdr.} = object
    private_context_size*: uint
    private_p_setup*: psa_drv_se_mac_setup_t
    private_p_update*: psa_drv_se_mac_update_t
    private_p_finish*: psa_drv_se_mac_finish_t
    private_p_finish_verify*: psa_drv_se_mac_finish_verify_t
    private_p_abort*: psa_drv_se_mac_abort_t
    private_p_mac*: psa_drv_se_mac_generate_t
    private_p_mac_verify*: psa_drv_se_mac_verify_t

  psa_drv_se_cipher_setup_t* {.importc, impcrypto_se_driverHdr.} = proc (
      drv_context: ptr psa_drv_se_context_t; op_context: pointer;
      key_slot: psa_key_slot_number_t; algorithm: psa_algorithm_t;
      direction: psa_encrypt_or_decrypt_t): psa_status_t {.cdecl.}
  psa_drv_se_cipher_set_iv_t* {.importc, impcrypto_se_driverHdr.} = proc (
      op_context: pointer; p_iv: ptr uint8; iv_length: uint): psa_status_t {.
      cdecl.}
  psa_drv_se_cipher_update_t* {.importc, impcrypto_se_driverHdr.} = proc (
      op_context: pointer; p_input: ptr uint8; input_size: uint;
      p_output: ptr uint8; output_size: uint; p_output_length: ptr uint): psa_status_t {.
      cdecl.}
  psa_drv_se_cipher_finish_t* {.importc, impcrypto_se_driverHdr.} = proc (
      op_context: pointer; p_output: ptr uint8; output_size: uint;
      p_output_length: ptr uint): psa_status_t {.cdecl.}
  psa_drv_se_cipher_abort_t* {.importc, impcrypto_se_driverHdr.} = proc (
      op_context: pointer): psa_status_t {.cdecl.}
  psa_drv_se_cipher_ecb_t* {.importc, impcrypto_se_driverHdr.} = proc (
      drv_context: ptr psa_drv_se_context_t; key_slot: psa_key_slot_number_t;
      algorithm: psa_algorithm_t; direction: psa_encrypt_or_decrypt_t;
      p_input: ptr uint8; input_size: uint; p_output: ptr uint8;
      output_size: uint): psa_status_t {.cdecl.}
  psa_drv_se_cipher_t* {.bycopy, importc, impcrypto_se_driverHdr.} = object
    private_context_size*: uint
    private_p_setup*: psa_drv_se_cipher_setup_t
    private_p_set_iv*: psa_drv_se_cipher_set_iv_t
    private_p_update*: psa_drv_se_cipher_update_t
    private_p_finish*: psa_drv_se_cipher_finish_t
    private_p_abort*: psa_drv_se_cipher_abort_t
    private_p_ecb*: psa_drv_se_cipher_ecb_t

  psa_drv_se_asymmetric_sign_t* {.importc, impcrypto_se_driverHdr.} = proc (
      drv_context: ptr psa_drv_se_context_t; key_slot: psa_key_slot_number_t;
      alg: psa_algorithm_t; p_hash: ptr uint8; hash_length: uint;
      p_signature: ptr uint8; signature_size: uint; p_signature_length: ptr uint): psa_status_t {.
      cdecl.}
  psa_drv_se_asymmetric_verify_t* {.importc, impcrypto_se_driverHdr.} = proc (
      drv_context: ptr psa_drv_se_context_t; key_slot: psa_key_slot_number_t;
      alg: psa_algorithm_t; p_hash: ptr uint8; hash_length: uint;
      p_signature: ptr uint8; signature_length: uint): psa_status_t {.cdecl.}
  psa_drv_se_asymmetric_encrypt_t* {.importc, impcrypto_se_driverHdr.} = proc (
      drv_context: ptr psa_drv_se_context_t; key_slot: psa_key_slot_number_t;
      alg: psa_algorithm_t; p_input: ptr uint8; input_length: uint;
      p_salt: ptr uint8; salt_length: uint; p_output: ptr uint8;
      output_size: uint; p_output_length: ptr uint): psa_status_t {.cdecl.}
  psa_drv_se_asymmetric_decrypt_t* {.importc, impcrypto_se_driverHdr.} = proc (
      drv_context: ptr psa_drv_se_context_t; key_slot: psa_key_slot_number_t;
      alg: psa_algorithm_t; p_input: ptr uint8; input_length: uint;
      p_salt: ptr uint8; salt_length: uint; p_output: ptr uint8;
      output_size: uint; p_output_length: ptr uint): psa_status_t {.cdecl.}
  psa_drv_se_asymmetric_t* {.bycopy, importc, impcrypto_se_driverHdr.} = object
    private_p_sign*: psa_drv_se_asymmetric_sign_t
    private_p_verify*: psa_drv_se_asymmetric_verify_t
    private_p_encrypt*: psa_drv_se_asymmetric_encrypt_t
    private_p_decrypt*: psa_drv_se_asymmetric_decrypt_t

  psa_drv_se_aead_encrypt_t* {.importc, impcrypto_se_driverHdr.} = proc (
      drv_context: ptr psa_drv_se_context_t; key_slot: psa_key_slot_number_t;
      algorithm: psa_algorithm_t; p_nonce: ptr uint8; nonce_length: uint;
      p_additional_data: ptr uint8; additional_data_length: uint;
      p_plaintext: ptr uint8; plaintext_length: uint; p_ciphertext: ptr uint8;
      ciphertext_size: uint; p_ciphertext_length: ptr uint): psa_status_t {.
      cdecl.}
  psa_drv_se_aead_decrypt_t* {.importc, impcrypto_se_driverHdr.} = proc (
      drv_context: ptr psa_drv_se_context_t; key_slot: psa_key_slot_number_t;
      algorithm: psa_algorithm_t; p_nonce: ptr uint8; nonce_length: uint;
      p_additional_data: ptr uint8; additional_data_length: uint;
      p_ciphertext: ptr uint8; ciphertext_length: uint; p_plaintext: ptr uint8;
      plaintext_size: uint; p_plaintext_length: ptr uint): psa_status_t {.cdecl.}
  psa_drv_se_aead_t* {.bycopy, importc, impcrypto_se_driverHdr.} = object
    private_p_encrypt*: psa_drv_se_aead_encrypt_t
    private_p_decrypt*: psa_drv_se_aead_decrypt_t

  psa_drv_se_allocate_key_t* {.importc, impcrypto_se_driverHdr.} = proc (
      drv_context: ptr psa_drv_se_context_t; persistent_data: pointer;
      attributes: ptr psa_key_attributes_t; `method`: psa_key_creation_method_t;
      key_slot: ptr psa_key_slot_number_t): psa_status_t {.cdecl.}
  psa_drv_se_validate_slot_number_t* {.importc, impcrypto_se_driverHdr.} = proc (
      drv_context: ptr psa_drv_se_context_t; persistent_data: pointer;
      attributes: ptr psa_key_attributes_t; `method`: psa_key_creation_method_t;
      key_slot: psa_key_slot_number_t): psa_status_t {.cdecl.}
  psa_drv_se_import_key_t* {.importc, impcrypto_se_driverHdr.} = proc (
      drv_context: ptr psa_drv_se_context_t; key_slot: psa_key_slot_number_t;
      attributes: ptr psa_key_attributes_t; data: ptr uint8; data_length: uint;
      bits: ptr uint): psa_status_t {.cdecl.}
  psa_drv_se_destroy_key_t* {.importc, impcrypto_se_driverHdr.} = proc (
      drv_context: ptr psa_drv_se_context_t; persistent_data: pointer;
      key_slot: psa_key_slot_number_t): psa_status_t {.cdecl.}
  psa_drv_se_export_key_t* {.importc, impcrypto_se_driverHdr.} = proc (
      drv_context: ptr psa_drv_se_context_t; key: psa_key_slot_number_t;
      p_data: ptr uint8; data_size: uint; p_data_length: ptr uint): psa_status_t {.
      cdecl.}
  psa_drv_se_generate_key_t* {.importc, impcrypto_se_driverHdr.} = proc (
      drv_context: ptr psa_drv_se_context_t; key_slot: psa_key_slot_number_t;
      attributes: ptr psa_key_attributes_t; pubkey: ptr uint8;
      pubkey_size: uint; pubkey_length: ptr uint): psa_status_t {.cdecl.}
  psa_drv_se_key_management_t* {.bycopy, importc, impcrypto_se_driverHdr.} = object
    private_p_allocate*: psa_drv_se_allocate_key_t
    private_p_validate_slot_number*: psa_drv_se_validate_slot_number_t
    private_p_import*: psa_drv_se_import_key_t
    private_p_generate*: psa_drv_se_generate_key_t
    private_p_destroy*: psa_drv_se_destroy_key_t
    private_p_export*: psa_drv_se_export_key_t
    private_p_export_public*: psa_drv_se_export_key_t

  psa_drv_se_key_derivation_setup_t* {.importc, impcrypto_se_driverHdr.} = proc (
      drv_context: ptr psa_drv_se_context_t; op_context: pointer;
      kdf_alg: psa_algorithm_t; source_key: psa_key_slot_number_t): psa_status_t {.
      cdecl.}
  psa_drv_se_key_derivation_collateral_t* {.importc, impcrypto_se_driverHdr.} = proc (
      op_context: pointer; collateral_id: uint32; p_collateral: ptr uint8;
      collateral_size: uint): psa_status_t {.cdecl.}
  psa_drv_se_key_derivation_derive_t* {.importc, impcrypto_se_driverHdr.} = proc (
      op_context: pointer; dest_key: psa_key_slot_number_t): psa_status_t {.
      cdecl.}
  psa_drv_se_key_derivation_export_t* {.importc, impcrypto_se_driverHdr.} = proc (
      op_context: pointer; p_output: ptr uint8; output_size: uint;
      p_output_length: ptr uint): psa_status_t {.cdecl.}
  psa_drv_se_key_derivation_t* {.bycopy, importc, impcrypto_se_driverHdr.} = object
    private_context_size*: uint
    private_p_setup*: psa_drv_se_key_derivation_setup_t
    private_p_collateral*: psa_drv_se_key_derivation_collateral_t
    private_p_derive*: psa_drv_se_key_derivation_derive_t
    private_p_export*: psa_drv_se_key_derivation_export_t

  psa_drv_se_t* {.bycopy, importc, impcrypto_se_driverHdr.} = object
    private_hal_version*: uint32
    private_persistent_data_size*: uint
    private_p_init*: psa_drv_se_init_t
    private_key_management*: ptr psa_drv_se_key_management_t
    private_mac*: ptr psa_drv_se_mac_t
    private_cipher*: ptr psa_drv_se_cipher_t
    private_aead*: ptr psa_drv_se_aead_t
    private_asymmetric*: ptr psa_drv_se_asymmetric_t
    private_derivation*: ptr psa_drv_se_key_derivation_t

proc psa_register_se_driver*(location: psa_key_location_t;
                             methods: ptr psa_drv_se_t): psa_status_t {.importc,
    cdecl, impcrypto_se_driverHdr.}
{.pop.}
