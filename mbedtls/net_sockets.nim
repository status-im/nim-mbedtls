{.used.}
import "csources"
{.compile: "./mbedtls/csources/library/net_sockets.c".}

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}

const
  MBEDTLS_ERR_NET_SOCKET_FAILED* = -0x00000042
  MBEDTLS_ERR_NET_CONNECT_FAILED* = -0x00000044
  MBEDTLS_ERR_NET_BIND_FAILED* = -0x00000046
  MBEDTLS_ERR_NET_LISTEN_FAILED* = -0x00000048
  MBEDTLS_ERR_NET_ACCEPT_FAILED* = -0x0000004A
  MBEDTLS_ERR_NET_RECV_FAILED* = -0x0000004C
  MBEDTLS_ERR_NET_SEND_FAILED* = -0x0000004E
  MBEDTLS_ERR_NET_CONN_RESET* = -0x00000050
  MBEDTLS_ERR_NET_UNKNOWN_HOST* = -0x00000052
  MBEDTLS_ERR_NET_BUFFER_TOO_SMALL* = -0x00000043
  MBEDTLS_ERR_NET_INVALID_CONTEXT* = -0x00000045
  MBEDTLS_ERR_NET_POLL_FAILED* = -0x00000047
  MBEDTLS_ERR_NET_BAD_INPUT_DATA* = -0x00000049
  MBEDTLS_NET_LISTEN_BACKLOG* = 10
  MBEDTLS_NET_PROTO_TCP* = 0
  MBEDTLS_NET_PROTO_UDP* = 1
  MBEDTLS_NET_POLL_READ* = 1
  MBEDTLS_NET_POLL_WRITE* = 2
type
  mbedtls_net_context* {.bycopy.} = object
    fd*: cint

proc mbedtls_net_init*(ctx: ptr mbedtls_net_context) {.importc, cdecl.}
proc mbedtls_net_connect*(ctx: ptr mbedtls_net_context; host: cstring;
                          port: cstring; proto: cint): cint {.importc, cdecl.}
proc mbedtls_net_bind*(ctx: ptr mbedtls_net_context; bind_ip: cstring;
                       port: cstring; proto: cint): cint {.importc, cdecl.}
proc mbedtls_net_accept*(bind_ctx: ptr mbedtls_net_context;
                         client_ctx: ptr mbedtls_net_context;
                         client_ip: pointer; buf_size: uint; ip_len: ptr uint): cint {.
    importc, cdecl.}
proc mbedtls_net_poll*(ctx: ptr mbedtls_net_context; rw: uint32; timeout: uint32): cint {.
    importc, cdecl.}
proc mbedtls_net_set_block*(ctx: ptr mbedtls_net_context): cint {.importc, cdecl.}
proc mbedtls_net_set_nonblock*(ctx: ptr mbedtls_net_context): cint {.importc,
    cdecl.}
proc mbedtls_net_usleep*(usec: culong) {.importc, cdecl.}
proc mbedtls_net_recv*(ctx: pointer; buf: ptr byte; len: uint): cint {.
    importc, cdecl.}
proc mbedtls_net_send*(ctx: pointer; buf: ptr byte; len: uint): cint {.
    importc, cdecl.}
proc mbedtls_net_recv_timeout*(ctx: pointer; buf: ptr byte; len: uint;
                               timeout: uint32): cint {.importc, cdecl.}
proc mbedtls_net_close*(ctx: ptr mbedtls_net_context) {.importc, cdecl.}
proc mbedtls_net_free*(ctx: ptr mbedtls_net_context) {.importc, cdecl.}
{.pop.}
