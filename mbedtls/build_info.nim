{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/csources/include".}
{.passc: "-I./mbedtls/csources/library".}

const
  MBEDTLS_VERSION_MAJOR* = 3
  MBEDTLS_VERSION_MINOR* = 4
  MBEDTLS_VERSION_PATCH* = 0
  MBEDTLS_VERSION_NUMBER* = 0x03040000
  MBEDTLS_VERSION_STRING* = "3.4.0"
  MBEDTLS_VERSION_STRING_FULL* = "mbed TLS 3.4.0"
{.pop.}
