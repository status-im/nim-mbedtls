import "ssl"
import "md"

{.compile: "./mbedtls/csources/library/ssl_cookie.c".}

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/csources/include".}
{.passc: "-I./mbedtls/csources/library".}

const
  MBEDTLS_SSL_COOKIE_TIMEOUT* = 60
type
  mbedtls_ssl_cookie_ctx* {.bycopy.} = object
    private_hmac_ctx*: mbedtls_md_context_t
    private_timeout*: culong

var
  mbedtls_ssl_cookie_write* {.importc.}: mbedtls_ssl_cookie_write_t
  mbedtls_ssl_cookie_check* {.importc.}: mbedtls_ssl_cookie_check_t
proc mbedtls_ssl_cookie_init*(ctx: ptr mbedtls_ssl_cookie_ctx) {.importc, cdecl.}
proc mbedtls_ssl_cookie_setup*(ctx: ptr mbedtls_ssl_cookie_ctx; f_rng: proc (
    a1: pointer; a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer): cint {.
    importc, cdecl.}
proc mbedtls_ssl_cookie_set_timeout*(ctx: ptr mbedtls_ssl_cookie_ctx;
                                     delay: culong) {.importc, cdecl.}
proc mbedtls_ssl_cookie_free*(ctx: ptr mbedtls_ssl_cookie_ctx) {.importc, cdecl.}
{.pop.}
