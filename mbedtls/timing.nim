{.compile: "./mbedtls/csources/library/timing.c".}

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/csources/include".}
{.passc: "-I./mbedtls/csources/library".}

type
  mbedtls_timing_hr_time* {.bycopy.} = object
    private_opaque*: array[4, uint64]

  mbedtls_timing_delay_context* {.bycopy.} = object
    private_timer*: mbedtls_timing_hr_time
    private_int_ms*: uint32
    private_fin_ms*: uint32

proc mbedtls_timing_get_timer*(val: ptr mbedtls_timing_hr_time; reset: cint): culong {.
    importc, cdecl.}
proc mbedtls_timing_set_delay*(data: pointer; int_ms: uint32; fin_ms: uint32) {.
    importc, cdecl.}
proc mbedtls_timing_get_delay*(data: pointer): cint {.importc, cdecl.}
proc mbedtls_timing_get_final_delay*(data: ptr mbedtls_timing_delay_context): uint32 {.
    importc, cdecl.}
{.pop.}
