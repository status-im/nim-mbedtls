{.used.}
import "csources"
import "ssl"
import "bignum"
import "ecp"
import "x509_crt"
import "ecdh"
import "utils"

# const 'MBEDTLS_PRINTF_MS_TIME' has unsupported value 'PRId64'

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}

defineEnum(mbedtls_debug_ecdh_attr)

const
  MBEDTLS_PRINTF_SIZET* = "zu"
  MBEDTLS_PRINTF_LONGLONG* = "lld"
  MBEDTLS_DEBUG_ECDH_Q* = (0).mbedtls_debug_ecdh_attr
  MBEDTLS_DEBUG_ECDH_QP* = (MBEDTLS_DEBUG_ECDH_Q + 1).mbedtls_debug_ecdh_attr
  MBEDTLS_DEBUG_ECDH_Z* = (MBEDTLS_DEBUG_ECDH_QP + 1).mbedtls_debug_ecdh_attr
proc mbedtls_debug_set_threshold*(threshold: cint) {.importc, cdecl.}
proc mbedtls_debug_print_msg*(ssl: ptr mbedtls_ssl_context; level: cint;
                              file: cstring; line: cint; format: cstring) {.
    importc, cdecl, varargs.}
proc mbedtls_debug_print_ret*(ssl: ptr mbedtls_ssl_context; level: cint;
                              file: cstring; line: cint; text: cstring;
                              ret: cint) {.importc, cdecl.}
proc mbedtls_debug_print_buf*(ssl: ptr mbedtls_ssl_context; level: cint;
                              file: cstring; line: cint; text: cstring;
                              buf: ptr byte; len: uint) {.importc, cdecl.}
proc mbedtls_debug_print_mpi*(ssl: ptr mbedtls_ssl_context; level: cint;
                              file: cstring; line: cint; text: cstring;
                              X: ptr mbedtls_mpi) {.importc, cdecl.}
proc mbedtls_debug_print_ecp*(ssl: ptr mbedtls_ssl_context; level: cint;
                              file: cstring; line: cint; text: cstring;
                              X: ptr mbedtls_ecp_point) {.importc, cdecl.}
proc mbedtls_debug_print_crt*(ssl: ptr mbedtls_ssl_context; level: cint;
                              file: cstring; line: cint; text: cstring;
                              crt: ptr mbedtls_x509_crt) {.importc, cdecl.}
proc mbedtls_debug_printf_ecdh*(ssl: ptr mbedtls_ssl_context; level: cint;
                                file: cstring; line: cint;
                                ecdh: ptr mbedtls_ecdh_context;
                                attr: mbedtls_debug_ecdh_attr) {.importc, cdecl.}
{.pop.}
