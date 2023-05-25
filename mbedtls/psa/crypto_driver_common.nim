{.used.}
import "../csources"
import "../utils"

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}

defineEnum(psa_encrypt_or_decrypt_t)

const
  PSA_CRYPTO_DRIVER_DECRYPT* = (0).psa_encrypt_or_decrypt_t
  PSA_CRYPTO_DRIVER_ENCRYPT* = (PSA_CRYPTO_DRIVER_DECRYPT + 1).psa_encrypt_or_decrypt_t
{.pop.}
