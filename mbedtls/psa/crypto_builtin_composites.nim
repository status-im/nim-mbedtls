# const 'MBEDTLS_PSA_HMAC_OPERATION_INIT' has unsupported value '{ 0, PSA_HASH_OPERATION_INIT, { 0 } }'
# const 'MBEDTLS_PSA_MAC_OPERATION_INIT' has unsupported value '{ 0, { 0 } }'
# const 'MBEDTLS_PSA_AEAD_OPERATION_INIT' has unsupported value '{ 0, 0, 0, 0, { 0 } }'
# const 'MBEDTLS_PSA_SIGN_HASH_INTERRUPTIBLE_OPERATION_INIT' has unsupported value '{ 0 }'
# const 'MBEDTLS_VERIFY_SIGN_HASH_INTERRUPTIBLE_OPERATION_INIT' has unsupported value '{ 0 }'
# const 'MBEDTLS_PSA_PAKE_OPERATION_INIT' has unsupported value '{ { 0 } }'

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.pragma: impcrypto_builtin_compositesHdr, header: "/home/lchenut/minnim/webrtc/mbedtls/include/psa/crypto_builtin_composites.h".}
{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/csources/include".}
{.passc: "-I./mbedtls/csources/library".}

const
  MBEDTLS_PSA_BUILTIN_AEAD* = 1
  MBEDTLS_PSA_BUILTIN_PAKE* = 1
  MBEDTLS_PSA_JPAKE_BUFFER_SIZE* = ((3 + typeof(3)(1) + typeof(3)(65) +
      typeof(3)(1) +
      typeof(3)(65) +
      typeof(3)(1) +
      typeof(3)(32)) *
      typeof(3)(2))
{.pop.}
