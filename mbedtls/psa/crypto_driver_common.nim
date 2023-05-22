import "../utils"

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.pragma: impcrypto_driver_commonHdr, header: "/home/lchenut/minnim/webrtc/mbedtls/include/psa/crypto_driver_common.h".}
{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/csources/include".}
{.passc: "-I./mbedtls/csources/library".}

defineEnum(psa_encrypt_or_decrypt_t)

const
  PSA_CRYPTO_DRIVER_DECRYPT* = (0).psa_encrypt_or_decrypt_t
  PSA_CRYPTO_DRIVER_ENCRYPT* = (PSA_CRYPTO_DRIVER_DECRYPT + 1).psa_encrypt_or_decrypt_t
{.pop.}
