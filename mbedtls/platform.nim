import "csources"
import "platform_time"

{.compile: "./mbedtls/csources/library/platform.c".}

# const 'MBEDTLS_PLATFORM_STD_SNPRINTF' has unsupported value 'snprintf'
# const 'MBEDTLS_PLATFORM_STD_VSNPRINTF' has unsupported value 'vsnprintf'
# const 'MBEDTLS_PLATFORM_STD_PRINTF' has unsupported value 'printf'
# const 'MBEDTLS_PLATFORM_STD_FPRINTF' has unsupported value 'fprintf'
# const 'MBEDTLS_PLATFORM_STD_CALLOC' has unsupported value 'calloc'
# const 'MBEDTLS_PLATFORM_STD_FREE' has unsupported value 'free'
# const 'MBEDTLS_PLATFORM_STD_SETBUF' has unsupported value 'setbuf'
# const 'MBEDTLS_PLATFORM_STD_EXIT' has unsupported value 'exit'
# const 'MBEDTLS_PLATFORM_STD_TIME' has unsupported value 'time'
# const 'MBEDTLS_PLATFORM_STD_EXIT_SUCCESS' has unsupported value 'EXIT_SUCCESS'
# const 'MBEDTLS_PLATFORM_STD_EXIT_FAILURE' has unsupported value 'EXIT_FAILURE'
# const 'MBEDTLS_PLATFORM_STD_NV_SEED_READ' has unsupported value 'mbedtls_platform_std_nv_seed_read'
# const 'MBEDTLS_PLATFORM_STD_NV_SEED_WRITE' has unsupported value 'mbedtls_platform_std_nv_seed_write'
# const 'mbedtls_free' has unsupported value 'free'
# const 'mbedtls_calloc' has unsupported value 'calloc'
# const 'mbedtls_fprintf' has unsupported value 'fprintf'
# const 'mbedtls_printf' has unsupported value 'printf'
# const 'mbedtls_snprintf' has unsupported value 'MBEDTLS_PLATFORM_STD_SNPRINTF'
# const 'mbedtls_vsnprintf' has unsupported value 'vsnprintf'
# const 'mbedtls_setbuf' has unsupported value 'setbuf'
# const 'mbedtls_exit' has unsupported value 'exit'
# const 'MBEDTLS_EXIT_SUCCESS' has unsupported value 'MBEDTLS_PLATFORM_STD_EXIT_SUCCESS'
# const 'MBEDTLS_EXIT_FAILURE' has unsupported value 'MBEDTLS_PLATFORM_STD_EXIT_FAILURE'

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}

const
  MBEDTLS_PLATFORM_STD_NV_SEED_FILE* = "seedfile"
type
  mbedtls_platform_context* {.bycopy.} = object
    private_dummy*: cchar

proc mbedtls_platform_setup*(ctx: ptr mbedtls_platform_context): cint {.importc,
    cdecl.}
proc mbedtls_platform_teardown*(ctx: ptr mbedtls_platform_context) {.importc,
    cdecl.}
{.pop.}
