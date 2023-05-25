import "csources"
import "md"
import "utils"

{.compile: "./mbedtls/csources/library/bignum.c".}
{.compile: "./mbedtls/csources/library/bignum_core.c".}
{.compile: "./mbedtls/csources/library/constant_time.c".}

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}

defineEnum(mbedtls_mpi_gen_prime_flag_t)

const
  MBEDTLS_ERR_MPI_FILE_IO_ERROR* = -0x00000002
  MBEDTLS_ERR_MPI_BAD_INPUT_DATA* = -0x00000004
  MBEDTLS_ERR_MPI_INVALID_CHARACTER* = -0x00000006
  MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL* = -0x00000008
  MBEDTLS_ERR_MPI_NEGATIVE_VALUE* = -0x0000000A
  MBEDTLS_ERR_MPI_DIVISION_BY_ZERO* = -0x0000000C
  MBEDTLS_ERR_MPI_NOT_ACCEPTABLE* = -0x0000000E
  MBEDTLS_ERR_MPI_ALLOC_FAILED* = -0x00000010
  MBEDTLS_MPI_MAX_LIMBS* = 10000
  MBEDTLS_MPI_WINDOW_SIZE* = 2
  MBEDTLS_MPI_MAX_SIZE* = 1024
  MBEDTLS_MPI_MAX_BITS* = (8 * typeof(8)(MBEDTLS_MPI_MAX_SIZE))
  MBEDTLS_MPI_MAX_BITS_SCALE100* = (100 * typeof(100)(MBEDTLS_MPI_MAX_BITS))
  MBEDTLS_LN_2_DIV_LN_10_SCALE100* = 332
  MBEDTLS_MPI_RW_BUFFER_SIZE* = ((typeof(MBEDTLS_MPI_MAX_BITS_SCALE100)((MBEDTLS_MPI_MAX_BITS_SCALE100 +
      typeof(MBEDTLS_MPI_MAX_BITS_SCALE100)(MBEDTLS_LN_2_DIV_LN_10_SCALE100) -
      typeof(MBEDTLS_MPI_MAX_BITS_SCALE100)(1)) /
      typeof(MBEDTLS_MPI_MAX_BITS_SCALE100)(MBEDTLS_LN_2_DIV_LN_10_SCALE100))) +
      typeof(MBEDTLS_MPI_MAX_BITS_SCALE100)(10) +
      typeof(MBEDTLS_MPI_MAX_BITS_SCALE100)(6))
  MBEDTLS_MPI_GEN_PRIME_FLAG_DH* = (0x00000001).mbedtls_mpi_gen_prime_flag_t
  MBEDTLS_MPI_GEN_PRIME_FLAG_LOW_ERR* = (0x00000002).mbedtls_mpi_gen_prime_flag_t
type
  mbedtls_mpi_sint* = int64
  mbedtls_mpi_uint* = uint64
  mbedtls_t_udbl* = cuint
  mbedtls_mpi* {.bycopy.} = object
    private_s*: cint
    private_n*: uint
    private_p*: ptr mbedtls_mpi_uint

proc mbedtls_mpi_init*(X: ptr mbedtls_mpi) {.importc, cdecl.}
proc mbedtls_mpi_free*(X: ptr mbedtls_mpi) {.importc, cdecl.}
proc mbedtls_mpi_grow*(X: ptr mbedtls_mpi; nblimbs: uint): cint {.importc, cdecl.}
proc mbedtls_mpi_shrink*(X: ptr mbedtls_mpi; nblimbs: uint): cint {.importc,
    cdecl.}
proc mbedtls_mpi_copy*(X: ptr mbedtls_mpi; Y: ptr mbedtls_mpi): cint {.importc,
    cdecl.}
proc mbedtls_mpi_swap*(X: ptr mbedtls_mpi; Y: ptr mbedtls_mpi) {.importc, cdecl.}
proc mbedtls_mpi_safe_cond_assign*(X: ptr mbedtls_mpi; Y: ptr mbedtls_mpi;
                                   assign: byte): cint {.importc, cdecl.}
proc mbedtls_mpi_safe_cond_swap*(X: ptr mbedtls_mpi; Y: ptr mbedtls_mpi;
                                 swap: byte): cint {.importc, cdecl.}
proc mbedtls_mpi_lset*(X: ptr mbedtls_mpi; z: mbedtls_mpi_sint): cint {.importc,
    cdecl.}
proc mbedtls_mpi_get_bit*(X: ptr mbedtls_mpi; pos: uint): cint {.importc, cdecl.}
proc mbedtls_mpi_set_bit*(X: ptr mbedtls_mpi; pos: uint; val: byte): cint {.
    importc, cdecl.}
proc mbedtls_mpi_lsb*(X: ptr mbedtls_mpi): uint {.importc, cdecl.}
proc mbedtls_mpi_bitlen*(X: ptr mbedtls_mpi): uint {.importc, cdecl.}
proc mbedtls_mpi_size*(X: ptr mbedtls_mpi): uint {.importc, cdecl.}
proc mbedtls_mpi_read_string*(X: ptr mbedtls_mpi; radix: cint; s: cstring): cint {.
    importc, cdecl.}
proc mbedtls_mpi_write_string*(X: ptr mbedtls_mpi; radix: cint; buf: cstring;
                               buflen: uint; olen: ptr uint): cint {.importc,
    cdecl.}
proc mbedtls_mpi_read_file*(X: ptr mbedtls_mpi; radix: cint; fin: File): cint {.
    importc, cdecl.}
proc mbedtls_mpi_write_file*(p: cstring; X: ptr mbedtls_mpi; radix: cint;
                             fout: File): cint {.importc, cdecl.}
proc mbedtls_mpi_read_binary*(X: ptr mbedtls_mpi; buf: ptr byte; buflen: uint): cint {.
    importc, cdecl.}
proc mbedtls_mpi_read_binary_le*(X: ptr mbedtls_mpi; buf: ptr byte;
                                 buflen: uint): cint {.importc, cdecl.}
proc mbedtls_mpi_write_binary*(X: ptr mbedtls_mpi; buf: ptr byte; buflen: uint): cint {.
    importc, cdecl.}
proc mbedtls_mpi_write_binary_le*(X: ptr mbedtls_mpi; buf: ptr byte;
                                  buflen: uint): cint {.importc, cdecl.}
proc mbedtls_mpi_shift_l*(X: ptr mbedtls_mpi; count: uint): cint {.importc,
    cdecl.}
proc mbedtls_mpi_shift_r*(X: ptr mbedtls_mpi; count: uint): cint {.importc,
    cdecl.}
proc mbedtls_mpi_cmp_abs*(X: ptr mbedtls_mpi; Y: ptr mbedtls_mpi): cint {.
    importc, cdecl.}
proc mbedtls_mpi_cmp_mpi*(X: ptr mbedtls_mpi; Y: ptr mbedtls_mpi): cint {.
    importc, cdecl.}
proc mbedtls_mpi_lt_mpi_ct*(X: ptr mbedtls_mpi; Y: ptr mbedtls_mpi;
                            ret: ptr cuint): cint {.importc, cdecl.}
proc mbedtls_mpi_cmp_int*(X: ptr mbedtls_mpi; z: mbedtls_mpi_sint): cint {.
    importc, cdecl.}
proc mbedtls_mpi_add_abs*(X: ptr mbedtls_mpi; A: ptr mbedtls_mpi;
                          B: ptr mbedtls_mpi): cint {.importc, cdecl.}
proc mbedtls_mpi_sub_abs*(X: ptr mbedtls_mpi; A: ptr mbedtls_mpi;
                          B: ptr mbedtls_mpi): cint {.importc, cdecl.}
proc mbedtls_mpi_add_mpi*(X: ptr mbedtls_mpi; A: ptr mbedtls_mpi;
                          B: ptr mbedtls_mpi): cint {.importc, cdecl.}
proc mbedtls_mpi_sub_mpi*(X: ptr mbedtls_mpi; A: ptr mbedtls_mpi;
                          B: ptr mbedtls_mpi): cint {.importc, cdecl.}
proc mbedtls_mpi_add_int*(X: ptr mbedtls_mpi; A: ptr mbedtls_mpi;
                          b: mbedtls_mpi_sint): cint {.importc, cdecl.}
proc mbedtls_mpi_sub_int*(X: ptr mbedtls_mpi; A: ptr mbedtls_mpi;
                          b: mbedtls_mpi_sint): cint {.importc, cdecl.}
proc mbedtls_mpi_mul_mpi*(X: ptr mbedtls_mpi; A: ptr mbedtls_mpi;
                          B: ptr mbedtls_mpi): cint {.importc, cdecl.}
proc mbedtls_mpi_mul_int*(X: ptr mbedtls_mpi; A: ptr mbedtls_mpi;
                          b: mbedtls_mpi_uint): cint {.importc, cdecl.}
proc mbedtls_mpi_div_mpi*(Q: ptr mbedtls_mpi; R: ptr mbedtls_mpi;
                          A: ptr mbedtls_mpi; B: ptr mbedtls_mpi): cint {.
    importc, cdecl.}
proc mbedtls_mpi_div_int*(Q: ptr mbedtls_mpi; R: ptr mbedtls_mpi;
                          A: ptr mbedtls_mpi; b: mbedtls_mpi_sint): cint {.
    importc, cdecl.}
proc mbedtls_mpi_mod_mpi*(R: ptr mbedtls_mpi; A: ptr mbedtls_mpi;
                          B: ptr mbedtls_mpi): cint {.importc, cdecl.}
proc mbedtls_mpi_mod_int*(r: ptr mbedtls_mpi_uint; A: ptr mbedtls_mpi;
                          b: mbedtls_mpi_sint): cint {.importc, cdecl.}
proc mbedtls_mpi_exp_mod*(X: ptr mbedtls_mpi; A: ptr mbedtls_mpi;
                          E: ptr mbedtls_mpi; N: ptr mbedtls_mpi;
                          prec_RR: ptr mbedtls_mpi): cint {.importc, cdecl.}
proc mbedtls_mpi_fill_random*(X: ptr mbedtls_mpi; size: uint; f_rng: proc (
    a1: pointer; a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer): cint {.
    importc, cdecl.}
proc mbedtls_mpi_random*(X: ptr mbedtls_mpi; min: mbedtls_mpi_sint;
                         N: ptr mbedtls_mpi; f_rng: proc (a1: pointer;
    a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer): cint {.importc,
    cdecl.}
proc mbedtls_mpi_gcd*(G: ptr mbedtls_mpi; A: ptr mbedtls_mpi; B: ptr mbedtls_mpi): cint {.
    importc, cdecl.}
proc mbedtls_mpi_inv_mod*(X: ptr mbedtls_mpi; A: ptr mbedtls_mpi;
                          N: ptr mbedtls_mpi): cint {.importc, cdecl.}
proc mbedtls_mpi_is_prime_ext*(X: ptr mbedtls_mpi; rounds: cint; f_rng: proc (
    a1: pointer; a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer): cint {.
    importc, cdecl.}
proc mbedtls_mpi_gen_prime*(X: ptr mbedtls_mpi; nbits: uint; flags: cint; f_rng: proc (
    a1: pointer; a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer): cint {.
    importc, cdecl.}
proc mbedtls_mpi_self_test*(verbose: cint): cint {.importc, cdecl.}
{.pop.}
