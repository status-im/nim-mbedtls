import "csources"
import "ssl"
import "platform_time"
import "ssl_ciphersuites"
import "cipher"

{.compile: "./mbedtls/csources/library/ssl_ticket.c".}

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}

const
  MBEDTLS_SSL_TICKET_MAX_KEY_BYTES* = 32
  MBEDTLS_SSL_TICKET_KEY_NAME_BYTES* = 4
type
  mbedtls_ssl_ticket_key* {.bycopy.} = object
    private_name*: array[4, byte]
    private_generation_time*: mbedtls_time_t
    private_ctx*: mbedtls_cipher_context_t

  mbedtls_ssl_ticket_context* {.bycopy.} = object
    private_keys*: array[2, mbedtls_ssl_ticket_key]
    private_active*: byte
    private_ticket_lifetime*: uint32
    private_f_rng*: proc (a1: pointer; a2: ptr byte; a3: uint): cint {.cdecl.}
    private_p_rng*: pointer

var
  mbedtls_ssl_ticket_write* {.importc.}: mbedtls_ssl_ticket_write_t
  mbedtls_ssl_ticket_parse* {.importc.}: mbedtls_ssl_ticket_parse_t
proc mbedtls_ssl_ticket_init*(ctx: ptr mbedtls_ssl_ticket_context) {.importc,
    cdecl.}
proc mbedtls_ssl_ticket_setup*(ctx: ptr mbedtls_ssl_ticket_context; f_rng: proc (
    a1: pointer; a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer;
                               cipher: mbedtls_cipher_type_t; lifetime: uint32): cint {.
    importc, cdecl.}
proc mbedtls_ssl_ticket_rotate*(ctx: ptr mbedtls_ssl_ticket_context;
                                name: ptr byte; nlength: uint; k: ptr byte;
                                klength: uint; lifetime: uint32): cint {.
    importc, cdecl.}
proc mbedtls_ssl_ticket_free*(ctx: ptr mbedtls_ssl_ticket_context) {.importc,
    cdecl.}
{.pop.}
