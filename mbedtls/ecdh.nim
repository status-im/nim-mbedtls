import "csources"
import "ecp"
import "bignum"
import "utils"

{.compile: "./mbedtls/csources/library/ecdh.c".}

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}

defineEnum(mbedtls_ecdh_side)
defineEnum(mbedtls_ecdh_variant)

const
  MBEDTLS_ECDH_OURS* = (0).mbedtls_ecdh_side
  MBEDTLS_ECDH_THEIRS* = (MBEDTLS_ECDH_OURS + 1).mbedtls_ecdh_side
  MBEDTLS_ECDH_VARIANT_NONE* = (0).mbedtls_ecdh_variant
  MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0* = (MBEDTLS_ECDH_VARIANT_NONE + 1).mbedtls_ecdh_variant
type
  mbedtls_ecdh_context_mbed* {.bycopy.} = object
    private_grp*: mbedtls_ecp_group
    private_d*: mbedtls_mpi
    private_Q*: mbedtls_ecp_point
    private_Qp*: mbedtls_ecp_point
    private_z*: mbedtls_mpi

  Union_ecdhh1* {.union, bycopy.} = object
    private_mbed_ecdh*: mbedtls_ecdh_context_mbed

  mbedtls_ecdh_context* {.bycopy.} = object
    private_point_format*: uint8
    private_grp_id*: mbedtls_ecp_group_id
    private_var*: mbedtls_ecdh_variant
    private_ctx*: Union_ecdhh1

proc mbedtls_ecdh_can_do*(gid: mbedtls_ecp_group_id): cint {.importc, cdecl.}
proc mbedtls_ecdh_gen_public*(grp: ptr mbedtls_ecp_group; d: ptr mbedtls_mpi;
                              Q: ptr mbedtls_ecp_point; f_rng: proc (
    a1: pointer; a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer): cint {.
    importc, cdecl.}
proc mbedtls_ecdh_compute_shared*(grp: ptr mbedtls_ecp_group;
                                  z: ptr mbedtls_mpi; Q: ptr mbedtls_ecp_point;
                                  d: ptr mbedtls_mpi; f_rng: proc (a1: pointer;
    a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer): cint {.importc,
    cdecl.}
proc mbedtls_ecdh_init*(ctx: ptr mbedtls_ecdh_context) {.importc, cdecl.}
proc mbedtls_ecdh_setup*(ctx: ptr mbedtls_ecdh_context;
                         grp_id: mbedtls_ecp_group_id): cint {.importc, cdecl.}
proc mbedtls_ecdh_free*(ctx: ptr mbedtls_ecdh_context) {.importc, cdecl.}
proc mbedtls_ecdh_make_params*(ctx: ptr mbedtls_ecdh_context; olen: ptr uint;
                               buf: ptr byte; blen: uint; f_rng: proc (
    a1: pointer; a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer): cint {.
    importc, cdecl.}
proc mbedtls_ecdh_read_params*(ctx: ptr mbedtls_ecdh_context;
                               buf: ptr ptr byte; `end`: ptr byte): cint {.
    importc, cdecl.}
proc mbedtls_ecdh_get_params*(ctx: ptr mbedtls_ecdh_context;
                              key: ptr mbedtls_ecp_keypair;
                              side: mbedtls_ecdh_side): cint {.importc, cdecl.}
proc mbedtls_ecdh_make_public*(ctx: ptr mbedtls_ecdh_context; olen: ptr uint;
                               buf: ptr byte; blen: uint; f_rng: proc (
    a1: pointer; a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer): cint {.
    importc, cdecl.}
proc mbedtls_ecdh_read_public*(ctx: ptr mbedtls_ecdh_context; buf: ptr byte;
                               blen: uint): cint {.importc, cdecl.}
proc mbedtls_ecdh_calc_secret*(ctx: ptr mbedtls_ecdh_context; olen: ptr uint;
                               buf: ptr byte; blen: uint; f_rng: proc (
    a1: pointer; a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer): cint {.
    importc, cdecl.}
{.pop.}
