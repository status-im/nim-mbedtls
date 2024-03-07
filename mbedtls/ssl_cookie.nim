{.used.}
import "csources"
import "ssl"
import "md"

{.compile: "./mbedtls/csources/library/ssl_cookie.c".}

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}

const
  MBEDTLS_SSL_COOKIE_TIMEOUT* = 60
type
  mbedtls_ssl_cookie_ctx* {.bycopy.} = object
    private_hmac_ctx*: mbedtls_md_context_t
    private_timeout*: culong

proc mbedtls_ssl_cookie_write*(ctx: pointer; p: ptr ptr byte;
                               `end`: ptr byte; info: ptr byte;
                               ilen: uint): cint {.importc, cdecl, gcsafe.}
proc mbedtls_ssl_cookie_check*(ctx: pointer; cookie: ptr byte; clen: uint;
                               info: ptr byte; ilen: uint): cint {.importc, cdecl, gcsafe.}
proc mbedtls_ssl_cookie_init*(ctx: ptr mbedtls_ssl_cookie_ctx) {.importc, cdecl.}
proc mbedtls_ssl_cookie_setup*(ctx: ptr mbedtls_ssl_cookie_ctx; f_rng: proc (
    a1: pointer; a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer): cint {.
    importc, cdecl.}
proc mbedtls_ssl_cookie_set_timeout*(ctx: ptr mbedtls_ssl_cookie_ctx;
                                     delay: culong) {.importc, cdecl.}
proc mbedtls_ssl_cookie_free*(ctx: ptr mbedtls_ssl_cookie_ctx) {.importc, cdecl.}
{.pop.}

import "ctr_drbg"

template mb_ssl_cookie_init*(ctx: mbedtls_ssl_cookie_ctx) =
  mbedtls_ssl_cookie_init(addr ctx)
template mb_ssl_cookie_setup*(ctx: mbedtls_ssl_cookie_ctx;
            f_rng: proc (a1: pointer; a2: ptr byte; a3: uint): cint {.cdecl.},
            p_rng: mbedtls_ctr_drbg_context) =
  let ret = mbedtls_ssl_cookie_setup(addr ctx, f_rng, addr p_rng)
  if ret != 0:
    raise newException(MbedTLSError, $(ret.mbedtls_high_level_strerr()))
