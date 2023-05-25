{.used.}
import "csources"
import "bignum"
import "md"

{.compile: "./mbedtls/csources/library/oid.c"}
{.compile: "./mbedtls/csources/library/rsa.c"}
{.compile: "./mbedtls/csources/library/rsa_alt_helpers.c"}

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}

const
  MBEDTLS_ERR_RSA_BAD_INPUT_DATA* = -0x00004080
  MBEDTLS_ERR_RSA_INVALID_PADDING* = -0x00004100
  MBEDTLS_ERR_RSA_KEY_GEN_FAILED* = -0x00004180
  MBEDTLS_ERR_RSA_KEY_CHECK_FAILED* = -0x00004200
  MBEDTLS_ERR_RSA_PUBLIC_FAILED* = -0x00004280
  MBEDTLS_ERR_RSA_PRIVATE_FAILED* = -0x00004300
  MBEDTLS_ERR_RSA_VERIFY_FAILED* = -0x00004380
  MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE* = -0x00004400
  MBEDTLS_ERR_RSA_RNG_FAILED* = -0x00004480
  MBEDTLS_RSA_PKCS_V15* = 0
  MBEDTLS_RSA_PKCS_V21* = 1
  MBEDTLS_RSA_SIGN* = 1
  MBEDTLS_RSA_CRYPT* = 2
  MBEDTLS_RSA_SALT_LEN_ANY* = -1
type
  mbedtls_rsa_context* {.bycopy.} = object
    private_ver*: cint
    private_len*: uint
    private_N*: mbedtls_mpi
    private_E*: mbedtls_mpi
    private_D*: mbedtls_mpi
    private_P*: mbedtls_mpi
    private_Q*: mbedtls_mpi
    private_DP*: mbedtls_mpi
    private_DQ*: mbedtls_mpi
    private_QP*: mbedtls_mpi
    private_RN*: mbedtls_mpi
    private_RP*: mbedtls_mpi
    private_RQ*: mbedtls_mpi
    private_Vi*: mbedtls_mpi
    private_Vf*: mbedtls_mpi
    private_padding*: cint
    private_hash_id*: cint

proc mbedtls_rsa_init*(ctx: ptr mbedtls_rsa_context) {.importc, cdecl.}
proc mbedtls_rsa_set_padding*(ctx: ptr mbedtls_rsa_context; padding: cint;
                              hash_id: mbedtls_md_type_t): cint {.importc, cdecl.}
proc mbedtls_rsa_get_padding_mode*(ctx: ptr mbedtls_rsa_context): cint {.
    importc, cdecl.}
proc mbedtls_rsa_get_md_alg*(ctx: ptr mbedtls_rsa_context): cint {.importc,
    cdecl.}
proc mbedtls_rsa_import*(ctx: ptr mbedtls_rsa_context; N: ptr mbedtls_mpi;
                         P: ptr mbedtls_mpi; Q: ptr mbedtls_mpi;
                         D: ptr mbedtls_mpi; E: ptr mbedtls_mpi): cint {.
    importc, cdecl.}
proc mbedtls_rsa_import_raw*(ctx: ptr mbedtls_rsa_context; N: ptr byte;
                             N_len: uint; P: ptr byte; P_len: uint;
                             Q: ptr byte; Q_len: uint; D: ptr byte;
                             D_len: uint; E: ptr byte; E_len: uint): cint {.
    importc, cdecl.}
proc mbedtls_rsa_complete*(ctx: ptr mbedtls_rsa_context): cint {.importc, cdecl.}
proc mbedtls_rsa_export*(ctx: ptr mbedtls_rsa_context; N: ptr mbedtls_mpi;
                         P: ptr mbedtls_mpi; Q: ptr mbedtls_mpi;
                         D: ptr mbedtls_mpi; E: ptr mbedtls_mpi): cint {.
    importc, cdecl.}
proc mbedtls_rsa_export_raw*(ctx: ptr mbedtls_rsa_context; N: ptr byte;
                             N_len: uint; P: ptr byte; P_len: uint;
                             Q: ptr byte; Q_len: uint; D: ptr byte;
                             D_len: uint; E: ptr byte; E_len: uint): cint {.
    importc, cdecl.}
proc mbedtls_rsa_export_crt*(ctx: ptr mbedtls_rsa_context; DP: ptr mbedtls_mpi;
                             DQ: ptr mbedtls_mpi; QP: ptr mbedtls_mpi): cint {.
    importc, cdecl.}
proc mbedtls_rsa_get_len*(ctx: ptr mbedtls_rsa_context): uint {.importc, cdecl.}
proc mbedtls_rsa_gen_key*(ctx: ptr mbedtls_rsa_context; f_rng: proc (
    a1: pointer; a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer;
                          nbits: cuint; exponent: cint): cint {.importc, cdecl.}
proc mbedtls_rsa_check_pubkey*(ctx: ptr mbedtls_rsa_context): cint {.importc,
    cdecl.}
proc mbedtls_rsa_check_privkey*(ctx: ptr mbedtls_rsa_context): cint {.importc,
    cdecl.}
proc mbedtls_rsa_check_pub_priv*(pub: ptr mbedtls_rsa_context;
                                 prv: ptr mbedtls_rsa_context): cint {.importc,
    cdecl.}
proc mbedtls_rsa_public*(ctx: ptr mbedtls_rsa_context; input: ptr byte;
                         output: ptr byte): cint {.importc, cdecl.}
proc mbedtls_rsa_private*(ctx: ptr mbedtls_rsa_context; f_rng: proc (
    a1: pointer; a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer;
                          input: ptr byte; output: ptr byte): cint {.
    importc, cdecl.}
proc mbedtls_rsa_pkcs1_encrypt*(ctx: ptr mbedtls_rsa_context; f_rng: proc (
    a1: pointer; a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer;
                                ilen: uint; input: ptr byte;
                                output: ptr byte): cint {.importc, cdecl.}
proc mbedtls_rsa_rsaes_pkcs1_v15_encrypt*(ctx: ptr mbedtls_rsa_context;
    f_rng: proc (a1: pointer; a2: ptr byte; a3: uint): cint {.cdecl.};
    p_rng: pointer; ilen: uint; input: ptr byte; output: ptr byte): cint {.
    importc, cdecl.}
proc mbedtls_rsa_rsaes_oaep_encrypt*(ctx: ptr mbedtls_rsa_context; f_rng: proc (
    a1: pointer; a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer;
                                     label: ptr byte; label_len: uint;
                                     ilen: uint; input: ptr byte;
                                     output: ptr byte): cint {.importc, cdecl.}
proc mbedtls_rsa_pkcs1_decrypt*(ctx: ptr mbedtls_rsa_context; f_rng: proc (
    a1: pointer; a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer;
                                olen: ptr uint; input: ptr byte;
                                output: ptr byte; output_max_len: uint): cint {.
    importc, cdecl.}
proc mbedtls_rsa_rsaes_pkcs1_v15_decrypt*(ctx: ptr mbedtls_rsa_context;
    f_rng: proc (a1: pointer; a2: ptr byte; a3: uint): cint {.cdecl.};
    p_rng: pointer; olen: ptr uint; input: ptr byte; output: ptr byte;
    output_max_len: uint): cint {.importc, cdecl.}
proc mbedtls_rsa_rsaes_oaep_decrypt*(ctx: ptr mbedtls_rsa_context; f_rng: proc (
    a1: pointer; a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer;
                                     label: ptr byte; label_len: uint;
                                     olen: ptr uint; input: ptr byte;
                                     output: ptr byte; output_max_len: uint): cint {.
    importc, cdecl.}
proc mbedtls_rsa_pkcs1_sign*(ctx: ptr mbedtls_rsa_context; f_rng: proc (
    a1: pointer; a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer;
                             md_alg: mbedtls_md_type_t; hashlen: cuint;
                             hash: ptr byte; sig: ptr byte): cint {.importc,
    cdecl.}
proc mbedtls_rsa_rsassa_pkcs1_v15_sign*(ctx: ptr mbedtls_rsa_context; f_rng: proc (
    a1: pointer; a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer;
                                        md_alg: mbedtls_md_type_t;
                                        hashlen: cuint; hash: ptr byte;
                                        sig: ptr byte): cint {.importc, cdecl.}
proc mbedtls_rsa_rsassa_pss_sign_ext*(ctx: ptr mbedtls_rsa_context; f_rng: proc (
    a1: pointer; a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer;
                                      md_alg: mbedtls_md_type_t; hashlen: cuint;
                                      hash: ptr byte; saltlen: cint;
                                      sig: ptr byte): cint {.importc, cdecl.}
proc mbedtls_rsa_rsassa_pss_sign*(ctx: ptr mbedtls_rsa_context; f_rng: proc (
    a1: pointer; a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer;
                                  md_alg: mbedtls_md_type_t; hashlen: cuint;
                                  hash: ptr byte; sig: ptr byte): cint {.
    importc, cdecl.}
proc mbedtls_rsa_pkcs1_verify*(ctx: ptr mbedtls_rsa_context;
                               md_alg: mbedtls_md_type_t; hashlen: cuint;
                               hash: ptr byte; sig: ptr byte): cint {.
    importc, cdecl.}
proc mbedtls_rsa_rsassa_pkcs1_v15_verify*(ctx: ptr mbedtls_rsa_context;
    md_alg: mbedtls_md_type_t; hashlen: cuint; hash: ptr byte; sig: ptr byte): cint {.
    importc, cdecl.}
proc mbedtls_rsa_rsassa_pss_verify*(ctx: ptr mbedtls_rsa_context;
                                    md_alg: mbedtls_md_type_t; hashlen: cuint;
                                    hash: ptr byte; sig: ptr byte): cint {.
    importc, cdecl.}
proc mbedtls_rsa_rsassa_pss_verify_ext*(ctx: ptr mbedtls_rsa_context;
                                        md_alg: mbedtls_md_type_t;
                                        hashlen: cuint; hash: ptr byte;
                                        mgf1_hash_id: mbedtls_md_type_t;
                                        expected_salt_len: cint; sig: ptr byte): cint {.
    importc, cdecl.}
proc mbedtls_rsa_copy*(dst: ptr mbedtls_rsa_context;
                       src: ptr mbedtls_rsa_context): cint {.importc, cdecl.}
proc mbedtls_rsa_free*(ctx: ptr mbedtls_rsa_context) {.importc, cdecl.}
proc mbedtls_rsa_self_test*(verbose: cint): cint {.importc, cdecl.}
{.pop.}
