import "bignum"
import "utils"

{.compile: "./mbedtls/csources/library/ecp.c".}
{.compile: "./mbedtls/csources/library/ecp_curves.c".}

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/csources/include".}
{.passc: "-I./mbedtls/csources/library".}

defineEnum(mbedtls_ecp_group_id)
defineEnum(mbedtls_ecp_curve_type)
defineEnum(mbedtls_ecp_modulus_type)

const
  MBEDTLS_ERR_ECP_BAD_INPUT_DATA* = -0x00004F80
  MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL* = -0x00004F00
  MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE* = -0x00004E80
  MBEDTLS_ERR_ECP_VERIFY_FAILED* = -0x00004E00
  MBEDTLS_ERR_ECP_ALLOC_FAILED* = -0x00004D80
  MBEDTLS_ERR_ECP_RANDOM_FAILED* = -0x00004D00
  MBEDTLS_ERR_ECP_INVALID_KEY* = -0x00004C80
  MBEDTLS_ERR_ECP_SIG_LEN_MISMATCH* = -0x00004C00
  MBEDTLS_ERR_ECP_IN_PROGRESS* = -0x00004B00
  MBEDTLS_ECP_DP_NONE* = (0).mbedtls_ecp_group_id
  MBEDTLS_ECP_DP_SECP192R1* = (MBEDTLS_ECP_DP_NONE + 1).mbedtls_ecp_group_id
  MBEDTLS_ECP_DP_SECP224R1* = (MBEDTLS_ECP_DP_SECP192R1 + 1).mbedtls_ecp_group_id
  MBEDTLS_ECP_DP_SECP256R1* = (MBEDTLS_ECP_DP_SECP224R1 + 1).mbedtls_ecp_group_id
  MBEDTLS_ECP_DP_SECP384R1* = (MBEDTLS_ECP_DP_SECP256R1 + 1).mbedtls_ecp_group_id
  MBEDTLS_ECP_DP_SECP521R1* = (MBEDTLS_ECP_DP_SECP384R1 + 1).mbedtls_ecp_group_id
  MBEDTLS_ECP_DP_BP256R1* = (MBEDTLS_ECP_DP_SECP521R1 + 1).mbedtls_ecp_group_id
  MBEDTLS_ECP_DP_BP384R1* = (MBEDTLS_ECP_DP_BP256R1 + 1).mbedtls_ecp_group_id
  MBEDTLS_ECP_DP_BP512R1* = (MBEDTLS_ECP_DP_BP384R1 + 1).mbedtls_ecp_group_id
  MBEDTLS_ECP_DP_CURVE25519* = (MBEDTLS_ECP_DP_BP512R1 + 1).mbedtls_ecp_group_id
  MBEDTLS_ECP_DP_SECP192K1* = (MBEDTLS_ECP_DP_CURVE25519 + 1).mbedtls_ecp_group_id
  MBEDTLS_ECP_DP_SECP224K1* = (MBEDTLS_ECP_DP_SECP192K1 + 1).mbedtls_ecp_group_id
  MBEDTLS_ECP_DP_SECP256K1* = (MBEDTLS_ECP_DP_SECP224K1 + 1).mbedtls_ecp_group_id
  MBEDTLS_ECP_DP_CURVE448* = (MBEDTLS_ECP_DP_SECP256K1 + 1).mbedtls_ecp_group_id
  MBEDTLS_ECP_DP_MAX* = 14
  MBEDTLS_ECP_TYPE_NONE* = (0).mbedtls_ecp_curve_type
  MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS* = (MBEDTLS_ECP_TYPE_NONE + 1).mbedtls_ecp_curve_type
  MBEDTLS_ECP_TYPE_MONTGOMERY* = (MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS + 1).mbedtls_ecp_curve_type
  MBEDTLS_ECP_MOD_NONE* = (0).mbedtls_ecp_modulus_type
  MBEDTLS_ECP_MOD_COORDINATE* = (MBEDTLS_ECP_MOD_NONE + 1).mbedtls_ecp_modulus_type
  MBEDTLS_ECP_MOD_SCALAR* = (MBEDTLS_ECP_MOD_COORDINATE + 1).mbedtls_ecp_modulus_type
  MBEDTLS_ECP_WINDOW_SIZE* = 4
  MBEDTLS_ECP_FIXED_POINT_OPTIM* = 1
  MBEDTLS_ECP_MAX_BITS* = 521
  MBEDTLS_ECP_MAX_BYTES* = (typeof(MBEDTLS_ECP_MAX_BITS)((
      MBEDTLS_ECP_MAX_BITS + typeof(MBEDTLS_ECP_MAX_BITS)(7)) /
      typeof(MBEDTLS_ECP_MAX_BITS)(8)))
  MBEDTLS_ECP_MAX_PT_LEN* = (2 * typeof(2)(MBEDTLS_ECP_MAX_BYTES) + typeof(2)(1))
  MBEDTLS_ECP_PF_UNCOMPRESSED* = 0
  MBEDTLS_ECP_PF_COMPRESSED* = 1
  MBEDTLS_ECP_TLS_NAMED_CURVE* = 3
type
  mbedtls_ecp_curve_info* {.bycopy.} = object
    grp_id*: mbedtls_ecp_group_id
    tls_id*: uint16
    bit_size*: uint16
    name*: cstring

  mbedtls_ecp_point* {.bycopy.} = object
    private_X*: mbedtls_mpi
    private_Y*: mbedtls_mpi
    private_Z*: mbedtls_mpi

  mbedtls_ecp_group* {.bycopy.} = object
    id*: mbedtls_ecp_group_id
    P*: mbedtls_mpi
    A*: mbedtls_mpi
    B*: mbedtls_mpi
    G*: mbedtls_ecp_point
    N*: mbedtls_mpi
    pbits*: uint
    nbits*: uint
    private_h*: cuint
    private_modp*: proc (a1: ptr mbedtls_mpi): cint {.cdecl.}
    private_t_pre*: proc (a1: ptr mbedtls_ecp_point; a2: pointer): cint {.cdecl.}
    private_t_post*: proc (a1: ptr mbedtls_ecp_point; a2: pointer): cint {.cdecl.}
    private_t_data*: pointer
    private_T*: ptr mbedtls_ecp_point
    private_T_size*: uint

  mbedtls_ecp_restart_ctx* = object
  mbedtls_ecp_keypair* {.bycopy.} = object
    private_grp*: mbedtls_ecp_group
    private_d*: mbedtls_mpi
    private_Q*: mbedtls_ecp_point

proc mbedtls_ecp_get_type*(grp: ptr mbedtls_ecp_group): mbedtls_ecp_curve_type {.
    importc, cdecl.}
proc mbedtls_ecp_curve_list*(): ptr mbedtls_ecp_curve_info {.importc, cdecl.}
proc mbedtls_ecp_grp_id_list*(): ptr mbedtls_ecp_group_id {.importc, cdecl.}
proc mbedtls_ecp_curve_info_from_grp_id*(grp_id: mbedtls_ecp_group_id): ptr mbedtls_ecp_curve_info {.
    importc, cdecl.}
proc mbedtls_ecp_curve_info_from_tls_id*(tls_id: uint16): ptr mbedtls_ecp_curve_info {.
    importc, cdecl.}
proc mbedtls_ecp_curve_info_from_name*(name: cstring): ptr mbedtls_ecp_curve_info {.
    importc, cdecl.}
proc mbedtls_ecp_point_init*(pt: ptr mbedtls_ecp_point) {.importc, cdecl.}
proc mbedtls_ecp_group_init*(grp: ptr mbedtls_ecp_group) {.importc, cdecl.}
proc mbedtls_ecp_keypair_init*(key: ptr mbedtls_ecp_keypair) {.importc, cdecl.}
proc mbedtls_ecp_point_free*(pt: ptr mbedtls_ecp_point) {.importc, cdecl.}
proc mbedtls_ecp_group_free*(grp: ptr mbedtls_ecp_group) {.importc, cdecl.}
proc mbedtls_ecp_keypair_free*(key: ptr mbedtls_ecp_keypair) {.importc, cdecl.}
proc mbedtls_ecp_copy*(P: ptr mbedtls_ecp_point; Q: ptr mbedtls_ecp_point): cint {.
    importc, cdecl.}
proc mbedtls_ecp_group_copy*(dst: ptr mbedtls_ecp_group;
                             src: ptr mbedtls_ecp_group): cint {.importc, cdecl.}
proc mbedtls_ecp_set_zero*(pt: ptr mbedtls_ecp_point): cint {.importc, cdecl.}
proc mbedtls_ecp_is_zero*(pt: ptr mbedtls_ecp_point): cint {.importc, cdecl.}
proc mbedtls_ecp_point_cmp*(P: ptr mbedtls_ecp_point; Q: ptr mbedtls_ecp_point): cint {.
    importc, cdecl.}
proc mbedtls_ecp_point_read_string*(P: ptr mbedtls_ecp_point; radix: cint;
                                    x: cstring; y: cstring): cint {.importc,
    cdecl.}
proc mbedtls_ecp_point_write_binary*(grp: ptr mbedtls_ecp_group;
                                     P: ptr mbedtls_ecp_point; format: cint;
                                     olen: ptr uint; buf: ptr byte;
                                     buflen: uint): cint {.importc, cdecl.}
proc mbedtls_ecp_point_read_binary*(grp: ptr mbedtls_ecp_group;
                                    P: ptr mbedtls_ecp_point; buf: ptr byte;
                                    ilen: uint): cint {.importc, cdecl.}
proc mbedtls_ecp_tls_read_point*(grp: ptr mbedtls_ecp_group;
                                 pt: ptr mbedtls_ecp_point; buf: ptr ptr byte;
                                 len: uint): cint {.importc, cdecl.}
proc mbedtls_ecp_tls_write_point*(grp: ptr mbedtls_ecp_group;
                                  pt: ptr mbedtls_ecp_point; format: cint;
                                  olen: ptr uint; buf: ptr byte; blen: uint): cint {.
    importc, cdecl.}
proc mbedtls_ecp_group_load*(grp: ptr mbedtls_ecp_group;
                             id: mbedtls_ecp_group_id): cint {.importc, cdecl.}
proc mbedtls_ecp_tls_read_group*(grp: ptr mbedtls_ecp_group;
                                 buf: ptr ptr byte; len: uint): cint {.
    importc, cdecl.}
proc mbedtls_ecp_tls_read_group_id*(grp: ptr mbedtls_ecp_group_id;
                                    buf: ptr ptr byte; len: uint): cint {.
    importc, cdecl.}
proc mbedtls_ecp_tls_write_group*(grp: ptr mbedtls_ecp_group; olen: ptr uint;
                                  buf: ptr byte; blen: uint): cint {.importc,
    cdecl.}
proc mbedtls_ecp_mul*(grp: ptr mbedtls_ecp_group; R: ptr mbedtls_ecp_point;
                      m: ptr mbedtls_mpi; P: ptr mbedtls_ecp_point; f_rng: proc (
    a1: pointer; a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer): cint {.
    importc, cdecl.}
proc mbedtls_ecp_mul_restartable*(grp: ptr mbedtls_ecp_group;
                                  R: ptr mbedtls_ecp_point; m: ptr mbedtls_mpi;
                                  P: ptr mbedtls_ecp_point; f_rng: proc (
    a1: pointer; a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer;
                                  rs_ctx: ptr mbedtls_ecp_restart_ctx): cint {.
    importc, cdecl.}
proc mbedtls_ecp_muladd*(grp: ptr mbedtls_ecp_group; R: ptr mbedtls_ecp_point;
                         m: ptr mbedtls_mpi; P: ptr mbedtls_ecp_point;
                         n: ptr mbedtls_mpi; Q: ptr mbedtls_ecp_point): cint {.
    importc, cdecl.}
proc mbedtls_ecp_muladd_restartable*(grp: ptr mbedtls_ecp_group;
                                     R: ptr mbedtls_ecp_point;
                                     m: ptr mbedtls_mpi;
                                     P: ptr mbedtls_ecp_point;
                                     n: ptr mbedtls_mpi;
                                     Q: ptr mbedtls_ecp_point;
                                     rs_ctx: ptr mbedtls_ecp_restart_ctx): cint {.
    importc, cdecl.}
proc mbedtls_ecp_check_pubkey*(grp: ptr mbedtls_ecp_group;
                               pt: ptr mbedtls_ecp_point): cint {.importc, cdecl.}
proc mbedtls_ecp_check_privkey*(grp: ptr mbedtls_ecp_group; d: ptr mbedtls_mpi): cint {.
    importc, cdecl.}
proc mbedtls_ecp_gen_privkey*(grp: ptr mbedtls_ecp_group; d: ptr mbedtls_mpi;
    f_rng: proc (a1: pointer; a2: ptr byte; a3: uint): cint {.cdecl.};
                              p_rng: pointer): cint {.importc, cdecl.}
proc mbedtls_ecp_gen_keypair_base*(grp: ptr mbedtls_ecp_group;
                                   G: ptr mbedtls_ecp_point; d: ptr mbedtls_mpi;
                                   Q: ptr mbedtls_ecp_point; f_rng: proc (
    a1: pointer; a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer): cint {.
    importc, cdecl.}
proc mbedtls_ecp_gen_keypair*(grp: ptr mbedtls_ecp_group; d: ptr mbedtls_mpi;
                              Q: ptr mbedtls_ecp_point; f_rng: proc (
    a1: pointer; a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer): cint {.
    importc, cdecl.}
proc mbedtls_ecp_gen_key*(grp_id: mbedtls_ecp_group_id;
                          key: ptr mbedtls_ecp_keypair; f_rng: proc (
    a1: pointer; a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer): cint {.
    importc, cdecl.}
proc mbedtls_ecp_read_key*(grp_id: mbedtls_ecp_group_id;
                           key: ptr mbedtls_ecp_keypair; buf: ptr byte;
                           buflen: uint): cint {.importc, cdecl.}
proc mbedtls_ecp_write_key*(key: ptr mbedtls_ecp_keypair; buf: ptr byte;
                            buflen: uint): cint {.importc, cdecl.}
proc mbedtls_ecp_check_pub_priv*(pub: ptr mbedtls_ecp_keypair;
                                 prv: ptr mbedtls_ecp_keypair; f_rng: proc (
    a1: pointer; a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer): cint {.
    importc, cdecl.}
proc mbedtls_ecp_export*(key: ptr mbedtls_ecp_keypair;
                         grp: ptr mbedtls_ecp_group; d: ptr mbedtls_mpi;
                         Q: ptr mbedtls_ecp_point): cint {.importc, cdecl.}
proc mbedtls_ecp_self_test*(verbose: cint): cint {.importc, cdecl.}
{.pop.}
