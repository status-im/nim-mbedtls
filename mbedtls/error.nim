{.compile: "./mbedtls/csources/library/error.c".}

# proc 'mbedtls_error_add' skipped - static inline procs cannot work with '--noHeader | -H'

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/csources/include".}
{.passc: "-I./mbedtls/csources/library".}

const
  MBEDTLS_ERR_ERROR_GENERIC_ERROR* = -0x00000001
  MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED* = -0x0000006E
  MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED* = -0x00000070
  MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED* = -0x00000072
proc mbedtls_strerror*(errnum: cint; buffer: cstring; buflen: uint) {.importc,
    cdecl.}
proc mbedtls_high_level_strerr*(error_code: cint): cstring {.importc, cdecl.}
proc mbedtls_low_level_strerr*(error_code: cint): cstring {.importc, cdecl.}
{.pop.}
