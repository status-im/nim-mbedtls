{.used.}
import "csources"
{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}

const
  MBEDTLS_ERR_THREADING_BAD_INPUT_DATA* = -0x0000001C
  MBEDTLS_ERR_THREADING_MUTEX_ERROR* = -0x0000001E
{.pop.}
