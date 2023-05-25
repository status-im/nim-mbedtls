import "../csources"
# const 'MBEDTLS_PSA_HASH_OPERATION_INIT' has unsupported value '{ 0, { 0 } }'
# const 'MBEDTLS_PSA_CIPHER_OPERATION_INIT' has unsupported value '{ 0, 0, 0, { 0 } }'

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}

const
  MBEDTLS_PSA_BUILTIN_CIPHER* = 1
{.pop.}
