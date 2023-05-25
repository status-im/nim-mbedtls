import "csources"
import "platform_time"

# const 'MBEDTLS_CHECK_RETURN' has unsupported value '__attribute__((__warn_unused_result__))'
# const 'MBEDTLS_CHECK_RETURN_CRITICAL' has unsupported value 'MBEDTLS_CHECK_RETURN'

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}

type tm {.importc: "struct tm", header: "<time.h>".} = object

proc mbedtls_platform_zeroize*(buf: pointer; len: uint) {.importc, cdecl.}
proc mbedtls_platform_gmtime_r*(tt: ptr mbedtls_time_t; tm_buf: ptr tm): ptr tm {.
    importc, cdecl.}
{.pop.}
