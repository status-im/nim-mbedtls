{.used.}
import "../csources"

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}

const
  PSA_WANT_ALG_CBC_NO_PADDING* = 1
  PSA_WANT_ALG_CBC_PKCS7* = 1
  PSA_WANT_ALG_CCM* = 1
  PSA_WANT_ALG_CCM_STAR_NO_TAG* = 1
  PSA_WANT_ALG_CMAC* = 1
  PSA_WANT_ALG_CFB* = 1
  PSA_WANT_ALG_CHACHA20_POLY1305* = 1
  PSA_WANT_ALG_CTR* = 1
  PSA_WANT_ALG_DETERMINISTIC_ECDSA* = 1
  PSA_WANT_ALG_ECB_NO_PADDING* = 1
  PSA_WANT_ALG_ECDH* = 1
  PSA_WANT_ALG_ECDSA* = 1
  PSA_WANT_ALG_JPAKE* = 1
  PSA_WANT_ALG_GCM* = 1
  PSA_WANT_ALG_HKDF* = 1
  PSA_WANT_ALG_HKDF_EXTRACT* = 1
  PSA_WANT_ALG_HKDF_EXPAND* = 1
  PSA_WANT_ALG_HMAC* = 1
  PSA_WANT_ALG_MD5* = 1
  PSA_WANT_ALG_OFB* = 1
  PSA_WANT_ALG_RIPEMD160* = 1
  PSA_WANT_ALG_RSA_OAEP* = 1
  PSA_WANT_ALG_RSA_PKCS1V15_CRYPT* = 1
  PSA_WANT_ALG_RSA_PKCS1V15_SIGN* = 1
  PSA_WANT_ALG_RSA_PSS* = 1
  PSA_WANT_ALG_SHA_1* = 1
  PSA_WANT_ALG_SHA_224* = 1
  PSA_WANT_ALG_SHA_256* = 1
  PSA_WANT_ALG_SHA_384* = 1
  PSA_WANT_ALG_SHA_512* = 1
  PSA_WANT_ALG_STREAM_CIPHER* = 1
  PSA_WANT_ALG_TLS12_PRF* = 1
  PSA_WANT_ALG_TLS12_PSK_TO_MS* = 1
  PSA_WANT_ALG_TLS12_ECJPAKE_TO_PMS* = 1
  PSA_WANT_ECC_BRAINPOOL_P_R1_256* = 1
  PSA_WANT_ECC_BRAINPOOL_P_R1_384* = 1
  PSA_WANT_ECC_BRAINPOOL_P_R1_512* = 1
  PSA_WANT_ECC_MONTGOMERY_255* = 1
  PSA_WANT_ECC_MONTGOMERY_448* = 1
  PSA_WANT_ECC_SECP_K1_192* = 1
  PSA_WANT_ECC_SECP_K1_256* = 1
  PSA_WANT_ECC_SECP_R1_192* = 1
  PSA_WANT_ECC_SECP_R1_224* = 1
  PSA_WANT_ECC_SECP_R1_256* = 1
  PSA_WANT_ECC_SECP_R1_384* = 1
  PSA_WANT_ECC_SECP_R1_521* = 1
  PSA_WANT_KEY_TYPE_DERIVE* = 1
  PSA_WANT_KEY_TYPE_PASSWORD* = 1
  PSA_WANT_KEY_TYPE_PASSWORD_HASH* = 1
  PSA_WANT_KEY_TYPE_HMAC* = 1
  PSA_WANT_KEY_TYPE_AES* = 1
  PSA_WANT_KEY_TYPE_ARIA* = 1
  PSA_WANT_KEY_TYPE_CAMELLIA* = 1
  PSA_WANT_KEY_TYPE_CHACHA20* = 1
  PSA_WANT_KEY_TYPE_DES* = 1
  PSA_WANT_KEY_TYPE_ECC_KEY_PAIR* = 1
  PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY* = 1
  PSA_WANT_KEY_TYPE_RAW_DATA* = 1
  PSA_WANT_KEY_TYPE_RSA_KEY_PAIR* = 1
  PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY* = 1
{.pop.}
