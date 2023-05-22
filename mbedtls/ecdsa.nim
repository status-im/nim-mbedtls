import "ecp"
import "bignum"
import "md"
import "hmac_drbg"
import "asn1write"

{.compile: "./mbedtls/csources/library/ecdsa.c".}

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/csources/include".}
{.passc: "-I./mbedtls/csources/library".}

type
  mbedtls_ecdsa_context* = mbedtls_ecp_keypair
  mbedtls_ecdsa_restart_ctx* = object
proc mbedtls_ecdsa_can_do*(gid: mbedtls_ecp_group_id): cint {.importc, cdecl.}
proc mbedtls_ecdsa_sign*(grp: ptr mbedtls_ecp_group; r: ptr mbedtls_mpi;
                         s: ptr mbedtls_mpi; d: ptr mbedtls_mpi;
                         buf: ptr byte; blen: uint; f_rng: proc (a1: pointer;
    a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer): cint {.importc,
    cdecl.}
proc mbedtls_ecdsa_sign_det_ext*(grp: ptr mbedtls_ecp_group; r: ptr mbedtls_mpi;
                                 s: ptr mbedtls_mpi; d: ptr mbedtls_mpi;
                                 buf: ptr byte; blen: uint;
                                 md_alg: mbedtls_md_type_t; f_rng_blind: proc (
    a1: pointer; a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng_blind: pointer): cint {.
    importc, cdecl.}
proc mbedtls_ecdsa_sign_restartable*(grp: ptr mbedtls_ecp_group;
                                     r: ptr mbedtls_mpi; s: ptr mbedtls_mpi;
                                     d: ptr mbedtls_mpi; buf: ptr byte;
                                     blen: uint; f_rng: proc (a1: pointer;
    a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer; f_rng_blind: proc (
    a1: pointer; a2: ptr byte; a3: uint): cint {.cdecl.};
                                     p_rng_blind: pointer;
                                     rs_ctx: ptr mbedtls_ecdsa_restart_ctx): cint {.
    importc, cdecl.}
proc mbedtls_ecdsa_sign_det_restartable*(grp: ptr mbedtls_ecp_group;
    r: ptr mbedtls_mpi; s: ptr mbedtls_mpi; d: ptr mbedtls_mpi; buf: ptr byte;
    blen: uint; md_alg: mbedtls_md_type_t;
    f_rng_blind: proc (a1: pointer; a2: ptr byte; a3: uint): cint {.cdecl.};
    p_rng_blind: pointer; rs_ctx: ptr mbedtls_ecdsa_restart_ctx): cint {.
    importc, cdecl.}
proc mbedtls_ecdsa_verify*(grp: ptr mbedtls_ecp_group; buf: ptr byte;
                           blen: uint; Q: ptr mbedtls_ecp_point;
                           r: ptr mbedtls_mpi; s: ptr mbedtls_mpi): cint {.
    importc, cdecl.}
proc mbedtls_ecdsa_verify_restartable*(grp: ptr mbedtls_ecp_group;
                                       buf: ptr byte; blen: uint;
                                       Q: ptr mbedtls_ecp_point;
                                       r: ptr mbedtls_mpi; s: ptr mbedtls_mpi;
                                       rs_ctx: ptr mbedtls_ecdsa_restart_ctx): cint {.
    importc, cdecl.}
proc mbedtls_ecdsa_write_signature*(ctx: ptr mbedtls_ecdsa_context;
                                    md_alg: mbedtls_md_type_t; hash: ptr byte;
                                    hlen: uint; sig: ptr byte; sig_size: uint;
                                    slen: ptr uint; f_rng: proc (a1: pointer;
    a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer): cint {.importc,
    cdecl.}
proc mbedtls_ecdsa_write_signature_restartable*(ctx: ptr mbedtls_ecdsa_context;
    md_alg: mbedtls_md_type_t; hash: ptr byte; hlen: uint; sig: ptr byte;
    sig_size: uint; slen: ptr uint;
    f_rng: proc (a1: pointer; a2: ptr byte; a3: uint): cint {.cdecl.};
    p_rng: pointer; rs_ctx: ptr mbedtls_ecdsa_restart_ctx): cint {.importc,
    cdecl.}
proc mbedtls_ecdsa_read_signature*(ctx: ptr mbedtls_ecdsa_context;
                                   hash: ptr byte; hlen: uint;
                                   sig: ptr byte; slen: uint): cint {.importc,
    cdecl.}
proc mbedtls_ecdsa_read_signature_restartable*(ctx: ptr mbedtls_ecdsa_context;
    hash: ptr byte; hlen: uint; sig: ptr byte; slen: uint;
    rs_ctx: ptr mbedtls_ecdsa_restart_ctx): cint {.importc, cdecl.}
proc mbedtls_ecdsa_genkey*(ctx: ptr mbedtls_ecdsa_context;
                           gid: mbedtls_ecp_group_id; f_rng: proc (a1: pointer;
    a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer): cint {.importc,
    cdecl.}
proc mbedtls_ecdsa_from_keypair*(ctx: ptr mbedtls_ecdsa_context;
                                 key: ptr mbedtls_ecp_keypair): cint {.importc,
    cdecl.}
proc mbedtls_ecdsa_init*(ctx: ptr mbedtls_ecdsa_context) {.importc, cdecl.}
proc mbedtls_ecdsa_free*(ctx: ptr mbedtls_ecdsa_context) {.importc, cdecl.}
{.pop.}
