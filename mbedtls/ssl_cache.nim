import "ssl"
import "platform_time"

{.compile: "./mbedtls/csources/library/ssl_cache.c".}

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/csources/include".}
{.passc: "-I./mbedtls/csources/library".}

const
  MBEDTLS_SSL_CACHE_DEFAULT_TIMEOUT* = 86400
  MBEDTLS_SSL_CACHE_DEFAULT_MAX_ENTRIES* = 50
type
  mbedtls_ssl_cache_context* {.bycopy.} = object
    private_chain*: ptr mbedtls_ssl_cache_entry
    private_timeout*: cint
    private_max_entries*: cint

  mbedtls_ssl_cache_entry* {.bycopy.} = object
    private_timestamp*: mbedtls_time_t
    private_session_id*: array[32, byte]
    private_session_id_len*: uint
    private_session*: ptr byte
    private_session_len*: uint
    private_next*: ptr mbedtls_ssl_cache_entry

proc mbedtls_ssl_cache_init*(cache: ptr mbedtls_ssl_cache_context) {.importc,
    cdecl.}
proc mbedtls_ssl_cache_get*(data: pointer; session_id: ptr byte;
                            session_id_len: uint;
                            session: ptr mbedtls_ssl_session): cint {.importc,
    cdecl.}
proc mbedtls_ssl_cache_set*(data: pointer; session_id: ptr byte;
                            session_id_len: uint;
                            session: ptr mbedtls_ssl_session): cint {.importc,
    cdecl.}
proc mbedtls_ssl_cache_remove*(data: pointer; session_id: ptr byte;
                               session_id_len: uint): cint {.importc, cdecl.}
proc mbedtls_ssl_cache_set_timeout*(cache: ptr mbedtls_ssl_cache_context;
                                    timeout: cint) {.importc, cdecl.}
proc mbedtls_ssl_cache_set_max_entries*(cache: ptr mbedtls_ssl_cache_context;
                                        max: cint) {.importc, cdecl.}
proc mbedtls_ssl_cache_free*(cache: ptr mbedtls_ssl_cache_context) {.importc,
    cdecl.}
{.pop.}
