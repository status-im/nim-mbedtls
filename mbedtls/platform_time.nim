{.used.}
{.compile: "./mbedtls/csources/library/platform_util.c".}

# const 'mbedtls_time' has unsupported value 'time'
{.push hint[ConvFromXtoItselfNotNeeded]: off.}

import std/time_t as std_time_t
type time_t* = std_time_t.Time

{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/csources/include".}
{.passc: "-I./mbedtls/csources/library".}

type
  mbedtls_time_t* = time_t
  mbedtls_ms_time_t* = int64
proc mbedtls_ms_time*(): mbedtls_ms_time_t {.importc, cdecl.}
{.pop.}
