{.used.}
import "csources"
import "cipher"
import "utils"

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}

defineEnum(mbedtls_nist_kw_mode_t)

const
  MBEDTLS_KW_MODE_KW* = (0).mbedtls_nist_kw_mode_t
  MBEDTLS_KW_MODE_KWP* = (1).mbedtls_nist_kw_mode_t
type
  mbedtls_nist_kw_context* {.bycopy.} = object
    private_cipher_ctx*: mbedtls_cipher_context_t

proc mbedtls_nist_kw_init*(ctx: ptr mbedtls_nist_kw_context) {.importc, cdecl.}
proc mbedtls_nist_kw_setkey*(ctx: ptr mbedtls_nist_kw_context;
                             cipher: mbedtls_cipher_id_t; key: ptr byte;
                             keybits: cuint; is_wrap: cint): cint {.importc,
    cdecl.}
proc mbedtls_nist_kw_free*(ctx: ptr mbedtls_nist_kw_context) {.importc, cdecl.}
proc mbedtls_nist_kw_wrap*(ctx: ptr mbedtls_nist_kw_context;
                           mode: mbedtls_nist_kw_mode_t; input: ptr byte;
                           in_len: uint; output: ptr byte; out_len: ptr uint;
                           out_size: uint): cint {.importc, cdecl.}
proc mbedtls_nist_kw_unwrap*(ctx: ptr mbedtls_nist_kw_context;
                             mode: mbedtls_nist_kw_mode_t; input: ptr byte;
                             in_len: uint; output: ptr byte;
                             out_len: ptr uint; out_size: uint): cint {.importc,
    cdecl.}
proc mbedtls_nist_kw_self_test*(verbose: cint): cint {.importc, cdecl.}
{.pop.}
