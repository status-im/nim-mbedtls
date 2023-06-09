{.used.}
import "csources"
import "pk"
import "utils"

{.compile: "./mbedtls/csources/library/ssl_ciphersuites.c".}

# proc 'mbedtls_ssl_ciphersuite_get_name' skipped - static inline procs cannot work with '--noHeader | -H'
# proc 'mbedtls_ssl_ciphersuite_has_pfs' skipped - static inline procs cannot work with '--noHeader | -H'
# proc 'mbedtls_ssl_ciphersuite_no_pfs' skipped - static inline procs cannot work with '--noHeader | -H'
# proc 'mbedtls_ssl_ciphersuite_uses_ecdh' skipped - static inline procs cannot work with '--noHeader | -H'
# proc 'mbedtls_ssl_ciphersuite_cert_req_allowed' skipped - static inline procs cannot work with '--noHeader | -H'
# proc 'mbedtls_ssl_ciphersuite_uses_srv_cert' skipped - static inline procs cannot work with '--noHeader | -H'
# proc 'mbedtls_ssl_ciphersuite_uses_dhe' skipped - static inline procs cannot work with '--noHeader | -H'
# proc 'mbedtls_ssl_ciphersuite_uses_ecdhe' skipped - static inline procs cannot work with '--noHeader | -H'
# proc 'mbedtls_ssl_ciphersuite_uses_server_signature' skipped - static inline procs cannot work with '--noHeader | -H'

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}

defineEnum(mbedtls_key_exchange_type_t)

const
  MBEDTLS_TLS_RSA_WITH_NULL_MD5* = 0x00000001
  MBEDTLS_TLS_RSA_WITH_NULL_SHA* = 0x00000002
  MBEDTLS_TLS_PSK_WITH_NULL_SHA* = 0x0000002C
  MBEDTLS_TLS_DHE_PSK_WITH_NULL_SHA* = 0x0000002D
  MBEDTLS_TLS_RSA_PSK_WITH_NULL_SHA* = 0x0000002E
  MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA* = 0x0000002F
  MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CBC_SHA* = 0x00000033
  MBEDTLS_TLS_RSA_WITH_AES_256_CBC_SHA* = 0x00000035
  MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CBC_SHA* = 0x00000039
  MBEDTLS_TLS_RSA_WITH_NULL_SHA256* = 0x0000003B
  MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA256* = 0x0000003C
  MBEDTLS_TLS_RSA_WITH_AES_256_CBC_SHA256* = 0x0000003D
  MBEDTLS_TLS_RSA_WITH_CAMELLIA_128_CBC_SHA* = 0x00000041
  MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA* = 0x00000045
  MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256* = 0x00000067
  MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256* = 0x0000006B
  MBEDTLS_TLS_RSA_WITH_CAMELLIA_256_CBC_SHA* = 0x00000084
  MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA* = 0x00000088
  MBEDTLS_TLS_PSK_WITH_AES_128_CBC_SHA* = 0x0000008C
  MBEDTLS_TLS_PSK_WITH_AES_256_CBC_SHA* = 0x0000008D
  MBEDTLS_TLS_DHE_PSK_WITH_AES_128_CBC_SHA* = 0x00000090
  MBEDTLS_TLS_DHE_PSK_WITH_AES_256_CBC_SHA* = 0x00000091
  MBEDTLS_TLS_RSA_PSK_WITH_AES_128_CBC_SHA* = 0x00000094
  MBEDTLS_TLS_RSA_PSK_WITH_AES_256_CBC_SHA* = 0x00000095
  MBEDTLS_TLS_RSA_WITH_AES_128_GCM_SHA256* = 0x0000009C
  MBEDTLS_TLS_RSA_WITH_AES_256_GCM_SHA384* = 0x0000009D
  MBEDTLS_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256* = 0x0000009E
  MBEDTLS_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384* = 0x0000009F
  MBEDTLS_TLS_PSK_WITH_AES_128_GCM_SHA256* = 0x000000A8
  MBEDTLS_TLS_PSK_WITH_AES_256_GCM_SHA384* = 0x000000A9
  MBEDTLS_TLS_DHE_PSK_WITH_AES_128_GCM_SHA256* = 0x000000AA
  MBEDTLS_TLS_DHE_PSK_WITH_AES_256_GCM_SHA384* = 0x000000AB
  MBEDTLS_TLS_RSA_PSK_WITH_AES_128_GCM_SHA256* = 0x000000AC
  MBEDTLS_TLS_RSA_PSK_WITH_AES_256_GCM_SHA384* = 0x000000AD
  MBEDTLS_TLS_PSK_WITH_AES_128_CBC_SHA256* = 0x000000AE
  MBEDTLS_TLS_PSK_WITH_AES_256_CBC_SHA384* = 0x000000AF
  MBEDTLS_TLS_PSK_WITH_NULL_SHA256* = 0x000000B0
  MBEDTLS_TLS_PSK_WITH_NULL_SHA384* = 0x000000B1
  MBEDTLS_TLS_DHE_PSK_WITH_AES_128_CBC_SHA256* = 0x000000B2
  MBEDTLS_TLS_DHE_PSK_WITH_AES_256_CBC_SHA384* = 0x000000B3
  MBEDTLS_TLS_DHE_PSK_WITH_NULL_SHA256* = 0x000000B4
  MBEDTLS_TLS_DHE_PSK_WITH_NULL_SHA384* = 0x000000B5
  MBEDTLS_TLS_RSA_PSK_WITH_AES_128_CBC_SHA256* = 0x000000B6
  MBEDTLS_TLS_RSA_PSK_WITH_AES_256_CBC_SHA384* = 0x000000B7
  MBEDTLS_TLS_RSA_PSK_WITH_NULL_SHA256* = 0x000000B8
  MBEDTLS_TLS_RSA_PSK_WITH_NULL_SHA384* = 0x000000B9
  MBEDTLS_TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256* = 0x000000BA
  MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256* = 0x000000BE
  MBEDTLS_TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256* = 0x000000C0
  MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256* = 0x000000C4
  MBEDTLS_TLS_ECDH_ECDSA_WITH_NULL_SHA* = 0x0000C001
  MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA* = 0x0000C004
  MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA* = 0x0000C005
  MBEDTLS_TLS_ECDHE_ECDSA_WITH_NULL_SHA* = 0x0000C006
  MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA* = 0x0000C009
  MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA* = 0x0000C00A
  MBEDTLS_TLS_ECDH_RSA_WITH_NULL_SHA* = 0x0000C00B
  MBEDTLS_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA* = 0x0000C00E
  MBEDTLS_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA* = 0x0000C00F
  MBEDTLS_TLS_ECDHE_RSA_WITH_NULL_SHA* = 0x0000C010
  MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA* = 0x0000C013
  MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA* = 0x0000C014
  MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256* = 0x0000C023
  MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384* = 0x0000C024
  MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256* = 0x0000C025
  MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384* = 0x0000C026
  MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256* = 0x0000C027
  MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384* = 0x0000C028
  MBEDTLS_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256* = 0x0000C029
  MBEDTLS_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384* = 0x0000C02A
  MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256* = 0x0000C02B
  MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384* = 0x0000C02C
  MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256* = 0x0000C02D
  MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384* = 0x0000C02E
  MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256* = 0x0000C02F
  MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384* = 0x0000C030
  MBEDTLS_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256* = 0x0000C031
  MBEDTLS_TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384* = 0x0000C032
  MBEDTLS_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA* = 0x0000C035
  MBEDTLS_TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA* = 0x0000C036
  MBEDTLS_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256* = 0x0000C037
  MBEDTLS_TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384* = 0x0000C038
  MBEDTLS_TLS_ECDHE_PSK_WITH_NULL_SHA* = 0x0000C039
  MBEDTLS_TLS_ECDHE_PSK_WITH_NULL_SHA256* = 0x0000C03A
  MBEDTLS_TLS_ECDHE_PSK_WITH_NULL_SHA384* = 0x0000C03B
  MBEDTLS_TLS_RSA_WITH_ARIA_128_CBC_SHA256* = 0x0000C03C
  MBEDTLS_TLS_RSA_WITH_ARIA_256_CBC_SHA384* = 0x0000C03D
  MBEDTLS_TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256* = 0x0000C044
  MBEDTLS_TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384* = 0x0000C045
  MBEDTLS_TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256* = 0x0000C048
  MBEDTLS_TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384* = 0x0000C049
  MBEDTLS_TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256* = 0x0000C04A
  MBEDTLS_TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384* = 0x0000C04B
  MBEDTLS_TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256* = 0x0000C04C
  MBEDTLS_TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384* = 0x0000C04D
  MBEDTLS_TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256* = 0x0000C04E
  MBEDTLS_TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384* = 0x0000C04F
  MBEDTLS_TLS_RSA_WITH_ARIA_128_GCM_SHA256* = 0x0000C050
  MBEDTLS_TLS_RSA_WITH_ARIA_256_GCM_SHA384* = 0x0000C051
  MBEDTLS_TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256* = 0x0000C052
  MBEDTLS_TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384* = 0x0000C053
  MBEDTLS_TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256* = 0x0000C05C
  MBEDTLS_TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384* = 0x0000C05D
  MBEDTLS_TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256* = 0x0000C05E
  MBEDTLS_TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384* = 0x0000C05F
  MBEDTLS_TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256* = 0x0000C060
  MBEDTLS_TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384* = 0x0000C061
  MBEDTLS_TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256* = 0x0000C062
  MBEDTLS_TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384* = 0x0000C063
  MBEDTLS_TLS_PSK_WITH_ARIA_128_CBC_SHA256* = 0x0000C064
  MBEDTLS_TLS_PSK_WITH_ARIA_256_CBC_SHA384* = 0x0000C065
  MBEDTLS_TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256* = 0x0000C066
  MBEDTLS_TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384* = 0x0000C067
  MBEDTLS_TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256* = 0x0000C068
  MBEDTLS_TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384* = 0x0000C069
  MBEDTLS_TLS_PSK_WITH_ARIA_128_GCM_SHA256* = 0x0000C06A
  MBEDTLS_TLS_PSK_WITH_ARIA_256_GCM_SHA384* = 0x0000C06B
  MBEDTLS_TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256* = 0x0000C06C
  MBEDTLS_TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384* = 0x0000C06D
  MBEDTLS_TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256* = 0x0000C06E
  MBEDTLS_TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384* = 0x0000C06F
  MBEDTLS_TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256* = 0x0000C070
  MBEDTLS_TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384* = 0x0000C071
  MBEDTLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256* = 0x0000C072
  MBEDTLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384* = 0x0000C073
  MBEDTLS_TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256* = 0x0000C074
  MBEDTLS_TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384* = 0x0000C075
  MBEDTLS_TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256* = 0x0000C076
  MBEDTLS_TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384* = 0x0000C077
  MBEDTLS_TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256* = 0x0000C078
  MBEDTLS_TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384* = 0x0000C079
  MBEDTLS_TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256* = 0x0000C07A
  MBEDTLS_TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384* = 0x0000C07B
  MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256* = 0x0000C07C
  MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384* = 0x0000C07D
  MBEDTLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256* = 0x0000C086
  MBEDTLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384* = 0x0000C087
  MBEDTLS_TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256* = 0x0000C088
  MBEDTLS_TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384* = 0x0000C089
  MBEDTLS_TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256* = 0x0000C08A
  MBEDTLS_TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384* = 0x0000C08B
  MBEDTLS_TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256* = 0x0000C08C
  MBEDTLS_TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384* = 0x0000C08D
  MBEDTLS_TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256* = 0x0000C08E
  MBEDTLS_TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384* = 0x0000C08F
  MBEDTLS_TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256* = 0x0000C090
  MBEDTLS_TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384* = 0x0000C091
  MBEDTLS_TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256* = 0x0000C092
  MBEDTLS_TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384* = 0x0000C093
  MBEDTLS_TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256* = 0x0000C094
  MBEDTLS_TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384* = 0x0000C095
  MBEDTLS_TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256* = 0x0000C096
  MBEDTLS_TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384* = 0x0000C097
  MBEDTLS_TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256* = 0x0000C098
  MBEDTLS_TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384* = 0x0000C099
  MBEDTLS_TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256* = 0x0000C09A
  MBEDTLS_TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384* = 0x0000C09B
  MBEDTLS_TLS_RSA_WITH_AES_128_CCM* = 0x0000C09C
  MBEDTLS_TLS_RSA_WITH_AES_256_CCM* = 0x0000C09D
  MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CCM* = 0x0000C09E
  MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CCM* = 0x0000C09F
  MBEDTLS_TLS_RSA_WITH_AES_128_CCM_8* = 0x0000C0A0
  MBEDTLS_TLS_RSA_WITH_AES_256_CCM_8* = 0x0000C0A1
  MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CCM_8* = 0x0000C0A2
  MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CCM_8* = 0x0000C0A3
  MBEDTLS_TLS_PSK_WITH_AES_128_CCM* = 0x0000C0A4
  MBEDTLS_TLS_PSK_WITH_AES_256_CCM* = 0x0000C0A5
  MBEDTLS_TLS_DHE_PSK_WITH_AES_128_CCM* = 0x0000C0A6
  MBEDTLS_TLS_DHE_PSK_WITH_AES_256_CCM* = 0x0000C0A7
  MBEDTLS_TLS_PSK_WITH_AES_128_CCM_8* = 0x0000C0A8
  MBEDTLS_TLS_PSK_WITH_AES_256_CCM_8* = 0x0000C0A9
  MBEDTLS_TLS_DHE_PSK_WITH_AES_128_CCM_8* = 0x0000C0AA
  MBEDTLS_TLS_DHE_PSK_WITH_AES_256_CCM_8* = 0x0000C0AB
  MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM* = 0x0000C0AC
  MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CCM* = 0x0000C0AD
  MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8* = 0x0000C0AE
  MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8* = 0x0000C0AF
  MBEDTLS_TLS_ECJPAKE_WITH_AES_128_CCM_8* = 0x0000C0FF
  MBEDTLS_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256* = 0x0000CCA8
  MBEDTLS_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256* = 0x0000CCA9
  MBEDTLS_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256* = 0x0000CCAA
  MBEDTLS_TLS_PSK_WITH_CHACHA20_POLY1305_SHA256* = 0x0000CCAB
  MBEDTLS_TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256* = 0x0000CCAC
  MBEDTLS_TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256* = 0x0000CCAD
  MBEDTLS_TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256* = 0x0000CCAE
  MBEDTLS_TLS1_3_AES_128_GCM_SHA256* = 0x00001301
  MBEDTLS_TLS1_3_AES_256_GCM_SHA384* = 0x00001302
  MBEDTLS_TLS1_3_CHACHA20_POLY1305_SHA256* = 0x00001303
  MBEDTLS_TLS1_3_AES_128_CCM_SHA256* = 0x00001304
  MBEDTLS_TLS1_3_AES_128_CCM_8_SHA256* = 0x00001305
  MBEDTLS_KEY_EXCHANGE_NONE* = (0).mbedtls_key_exchange_type_t
  MBEDTLS_KEY_EXCHANGE_RSA* = (MBEDTLS_KEY_EXCHANGE_NONE + 1).mbedtls_key_exchange_type_t
  MBEDTLS_KEY_EXCHANGE_DHE_RSA* = (MBEDTLS_KEY_EXCHANGE_RSA + 1).mbedtls_key_exchange_type_t
  MBEDTLS_KEY_EXCHANGE_ECDHE_RSA* = (MBEDTLS_KEY_EXCHANGE_DHE_RSA + 1).mbedtls_key_exchange_type_t
  MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA* = (MBEDTLS_KEY_EXCHANGE_ECDHE_RSA + 1).mbedtls_key_exchange_type_t
  MBEDTLS_KEY_EXCHANGE_PSK* = (MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA + 1).mbedtls_key_exchange_type_t
  MBEDTLS_KEY_EXCHANGE_DHE_PSK* = (MBEDTLS_KEY_EXCHANGE_PSK + 1).mbedtls_key_exchange_type_t
  MBEDTLS_KEY_EXCHANGE_RSA_PSK* = (MBEDTLS_KEY_EXCHANGE_DHE_PSK + 1).mbedtls_key_exchange_type_t
  MBEDTLS_KEY_EXCHANGE_ECDHE_PSK* = (MBEDTLS_KEY_EXCHANGE_RSA_PSK + 1).mbedtls_key_exchange_type_t
  MBEDTLS_KEY_EXCHANGE_ECDH_RSA* = (MBEDTLS_KEY_EXCHANGE_ECDHE_PSK + 1).mbedtls_key_exchange_type_t
  MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA* = (MBEDTLS_KEY_EXCHANGE_ECDH_RSA + 1).mbedtls_key_exchange_type_t
  MBEDTLS_KEY_EXCHANGE_ECJPAKE* = (MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA + 1).mbedtls_key_exchange_type_t
  MBEDTLS_CIPHERSUITE_WEAK* = 0x00000001
  MBEDTLS_CIPHERSUITE_SHORT_TAG* = 0x00000002
  MBEDTLS_CIPHERSUITE_NODTLS* = 0x00000004
type
  mbedtls_ssl_ciphersuite_t* {.bycopy.} = object
    private_id*: cint
    private_name*: cstring
    private_cipher*: uint8
    private_mac*: uint8
    private_key_exchange*: uint8
    private_flags*: uint8
    private_min_tls_version*: uint16
    private_max_tls_version*: uint16

proc mbedtls_ssl_list_ciphersuites*(): ptr cint {.importc, cdecl.}
proc mbedtls_ssl_ciphersuite_from_string*(ciphersuite_name: cstring): ptr mbedtls_ssl_ciphersuite_t {.
    importc, cdecl.}
proc mbedtls_ssl_ciphersuite_from_id*(ciphersuite_id: cint): ptr mbedtls_ssl_ciphersuite_t {.
    importc, cdecl.}
proc mbedtls_ssl_get_ciphersuite_sig_pk_alg*(info: ptr mbedtls_ssl_ciphersuite_t): mbedtls_pk_type_t {.
    importc, cdecl.}
proc mbedtls_ssl_get_ciphersuite_sig_alg*(info: ptr mbedtls_ssl_ciphersuite_t): mbedtls_pk_type_t {.
    importc, cdecl.}
proc mbedtls_ssl_ciphersuite_uses_ec*(info: ptr mbedtls_ssl_ciphersuite_t): cint {.
    importc, cdecl.}
proc mbedtls_ssl_ciphersuite_uses_psk*(info: ptr mbedtls_ssl_ciphersuite_t): cint {.
    importc, cdecl.}
proc mbedtls_ssl_ciphersuite_get_cipher_key_bitlen*(
    info: ptr mbedtls_ssl_ciphersuite_t): uint {.importc, cdecl.}
{.pop.}
