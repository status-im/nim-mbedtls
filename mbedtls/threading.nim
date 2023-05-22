{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/csources/include".}
{.passc: "-I./mbedtls/csources/library".}

const
  MBEDTLS_ERR_THREADING_BAD_INPUT_DATA* = -0x0000001C
  MBEDTLS_ERR_THREADING_MUTEX_ERROR* = -0x0000001E
{.pop.}
