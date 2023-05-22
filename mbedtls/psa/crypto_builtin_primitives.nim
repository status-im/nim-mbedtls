# const 'MBEDTLS_PSA_HASH_OPERATION_INIT' has unsupported value '{ 0, { 0 } }'
# const 'MBEDTLS_PSA_CIPHER_OPERATION_INIT' has unsupported value '{ 0, 0, 0, { 0 } }'

{.push hint[ConvFromXtoItselfNotNeeded]: off.}
{.pragma: impcrypto_builtin_primitivesHdr, header: "/home/lchenut/minnim/webrtc/mbedtls/include/psa/crypto_builtin_primitives.h".}
{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/csources/include".}
{.passc: "-I./mbedtls/csources/library".}

const
  MBEDTLS_PSA_BUILTIN_CIPHER* = 1
{.pop.}
