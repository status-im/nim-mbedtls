import "ecp"
import "bignum"
import "md"
import "hash_info"
import "platform_time"
import "utils"

{.compile: "./mbedtls/csources/library/ecjpake.c".}

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/csources/include".}
{.passc: "-I./mbedtls/csources/library".}

defineEnum(mbedtls_ecjpake_role)

const
  MBEDTLS_ECJPAKE_CLIENT* = (0).mbedtls_ecjpake_role
  MBEDTLS_ECJPAKE_SERVER* = (MBEDTLS_ECJPAKE_CLIENT + 1).mbedtls_ecjpake_role
type
  mbedtls_ecjpake_context* {.bycopy.} = object
    private_md_type*: mbedtls_md_type_t
    private_grp*: mbedtls_ecp_group
    private_role*: mbedtls_ecjpake_role
    private_point_format*: cint
    private_Xm1*: mbedtls_ecp_point
    private_Xm2*: mbedtls_ecp_point
    private_Xp1*: mbedtls_ecp_point
    private_Xp2*: mbedtls_ecp_point
    private_Xp*: mbedtls_ecp_point
    private_xm1_1*: mbedtls_mpi
    private_xm2_1*: mbedtls_mpi
    private_s*: mbedtls_mpi

proc mbedtls_ecjpake_init*(ctx: ptr mbedtls_ecjpake_context) {.importc, cdecl.}
proc mbedtls_ecjpake_setup*(ctx: ptr mbedtls_ecjpake_context;
                            role: mbedtls_ecjpake_role; hash: mbedtls_md_type_t;
                            curve: mbedtls_ecp_group_id; secret: ptr byte;
                            len: uint): cint {.importc, cdecl.}
proc mbedtls_ecjpake_set_point_format*(ctx: ptr mbedtls_ecjpake_context;
                                       point_format: cint): cint {.importc,
    cdecl.}
proc mbedtls_ecjpake_check*(ctx: ptr mbedtls_ecjpake_context): cint {.importc,
    cdecl.}
proc mbedtls_ecjpake_write_round_one*(ctx: ptr mbedtls_ecjpake_context;
                                      buf: ptr byte; len: uint;
                                      olen: ptr uint; f_rng: proc (a1: pointer;
    a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer): cint {.importc,
    cdecl.}
proc mbedtls_ecjpake_read_round_one*(ctx: ptr mbedtls_ecjpake_context;
                                     buf: ptr byte; len: uint): cint {.
    importc, cdecl.}
proc mbedtls_ecjpake_write_round_two*(ctx: ptr mbedtls_ecjpake_context;
                                      buf: ptr byte; len: uint;
                                      olen: ptr uint; f_rng: proc (a1: pointer;
    a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer): cint {.importc,
    cdecl.}
proc mbedtls_ecjpake_read_round_two*(ctx: ptr mbedtls_ecjpake_context;
                                     buf: ptr byte; len: uint): cint {.
    importc, cdecl.}
proc mbedtls_ecjpake_derive_secret*(ctx: ptr mbedtls_ecjpake_context;
                                    buf: ptr byte; len: uint; olen: ptr uint;
    f_rng: proc (a1: pointer; a2: ptr byte; a3: uint): cint {.cdecl.};
                                    p_rng: pointer): cint {.importc, cdecl.}
proc mbedtls_ecjpake_write_shared_key*(ctx: ptr mbedtls_ecjpake_context;
                                       buf: ptr byte; len: uint;
                                       olen: ptr uint; f_rng: proc (a1: pointer;
    a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer): cint {.importc,
    cdecl.}
proc mbedtls_ecjpake_free*(ctx: ptr mbedtls_ecjpake_context) {.importc, cdecl.}
proc mbedtls_ecjpake_self_test*(verbose: cint): cint {.importc, cdecl.}
{.pop.}
