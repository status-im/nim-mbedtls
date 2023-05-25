import "csources"
import "ssl_ciphersuites"
import "platform_time"
import "bignum"
import "ecp"
import "pk"
import "x509_crt"
import "x509_crl"
import "dhm"
import "utils"

{.compile: "./mbedtls/csources/library/debug.c".}
{.compile: "./mbedtls/csources/library/ssl_debug_helpers_generated.c".}
{.compile: "./mbedtls/csources/library/ssl_msg.c".}
{.compile: "./mbedtls/csources/library/ssl_tls12_server.c".}
{.compile: "./mbedtls/csources/library/ssl_tls.c".}
{.compile: "./mbedtls/csources/library/ssl_client.c".}
{.compile: "./mbedtls/csources/library/ssl_tls12_client.c".}

# const 'MBEDTLS_PREMASTER_SIZE' has unsupported value 'sizeof(union mbedtls_ssl_premaster_secret)'
# const 'MBEDTLS_TLS1_3_MD_MAX_SIZE' has unsupported value 'PSA_HASH_MAX_SIZE'
# proc 'mbedtls_ssl_context_get_config' skipped - static inline procs cannot work with '--noHeader | -H'
# proc 'mbedtls_ssl_conf_cert_cb' skipped - static inline procs cannot work with '--noHeader | -H'
# proc 'mbedtls_ssl_conf_set_user_data_p' skipped - static inline procs cannot work with '--noHeader | -H'
# proc 'mbedtls_ssl_conf_set_user_data_n' skipped - static inline procs cannot work with '--noHeader | -H'
# proc 'mbedtls_ssl_conf_get_user_data_p' skipped - static inline procs cannot work with '--noHeader | -H'
# proc 'mbedtls_ssl_conf_get_user_data_n' skipped - static inline procs cannot work with '--noHeader | -H'
# proc 'mbedtls_ssl_set_user_data_p' skipped - static inline procs cannot work with '--noHeader | -H'
# proc 'mbedtls_ssl_set_user_data_n' skipped - static inline procs cannot work with '--noHeader | -H'
# proc 'mbedtls_ssl_get_user_data_p' skipped - static inline procs cannot work with '--noHeader | -H'
# proc 'mbedtls_ssl_get_user_data_n' skipped - static inline procs cannot work with '--noHeader | -H'
# proc 'mbedtls_ssl_conf_dn_hints' skipped - static inline procs cannot work with '--noHeader | -H'
# proc 'mbedtls_ssl_conf_max_tls_version' skipped - static inline procs cannot work with '--noHeader | -H'
# proc 'mbedtls_ssl_conf_min_tls_version' skipped - static inline procs cannot work with '--noHeader | -H'
# proc 'mbedtls_ssl_get_version_number' skipped - static inline procs cannot work with '--noHeader | -H'
# proc 'mbedtls_ssl_is_handshake_over' skipped - static inline procs cannot work with '--noHeader | -H'

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}

defineEnum(mbedtls_ssl_states)
defineEnum(mbedtls_ssl_protocol_version)
defineEnum(mbedtls_tls_prf_types)
defineEnum(mbedtls_ssl_key_export_type)

const
  MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS* = -0x00007000
  MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE* = -0x00007080
  MBEDTLS_ERR_SSL_BAD_INPUT_DATA* = -0x00007100
  MBEDTLS_ERR_SSL_INVALID_MAC* = -0x00007180
  MBEDTLS_ERR_SSL_INVALID_RECORD* = -0x00007200
  MBEDTLS_ERR_SSL_CONN_EOF* = -0x00007280
  MBEDTLS_ERR_SSL_DECODE_ERROR* = -0x00007300
  MBEDTLS_ERR_SSL_NO_RNG* = -0x00007400
  MBEDTLS_ERR_SSL_NO_CLIENT_CERTIFICATE* = -0x00007480
  MBEDTLS_ERR_SSL_UNSUPPORTED_EXTENSION* = -0x00007500
  MBEDTLS_ERR_SSL_NO_APPLICATION_PROTOCOL* = -0x00007580
  MBEDTLS_ERR_SSL_PRIVATE_KEY_REQUIRED* = -0x00007600
  MBEDTLS_ERR_SSL_CA_CHAIN_REQUIRED* = -0x00007680
  MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE* = -0x00007700
  MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE* = -0x00007780
  MBEDTLS_ERR_SSL_UNRECOGNIZED_NAME* = -0x00007800
  MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY* = -0x00007880
  MBEDTLS_ERR_SSL_BAD_CERTIFICATE* = -0x00007A00
  MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET* = -0x00007B00
  MBEDTLS_ERR_SSL_CANNOT_READ_EARLY_DATA* = -0x00007B80
  MBEDTLS_ERR_SSL_CANNOT_WRITE_EARLY_DATA* = -0x00007C00
  MBEDTLS_ERR_SSL_CACHE_ENTRY_NOT_FOUND* = -0x00007E80
  MBEDTLS_ERR_SSL_ALLOC_FAILED* = -0x00007F00
  MBEDTLS_ERR_SSL_HW_ACCEL_FAILED* = -0x00007F80
  MBEDTLS_ERR_SSL_HW_ACCEL_FALLTHROUGH* = -0x00006F80
  MBEDTLS_ERR_SSL_BAD_PROTOCOL_VERSION* = -0x00006E80
  MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE* = -0x00006E00
  MBEDTLS_ERR_SSL_SESSION_TICKET_EXPIRED* = -0x00006D80
  MBEDTLS_ERR_SSL_PK_TYPE_MISMATCH* = -0x00006D00
  MBEDTLS_ERR_SSL_UNKNOWN_IDENTITY* = -0x00006C80
  MBEDTLS_ERR_SSL_INTERNAL_ERROR* = -0x00006C00
  MBEDTLS_ERR_SSL_COUNTER_WRAPPING* = -0x00006B80
  MBEDTLS_ERR_SSL_WAITING_SERVER_HELLO_RENEGO* = -0x00006B00
  MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED* = -0x00006A80
  MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL* = -0x00006A00
  MBEDTLS_ERR_SSL_WANT_READ* = -0x00006900
  MBEDTLS_ERR_SSL_WANT_WRITE* = -0x00006880
  MBEDTLS_ERR_SSL_TIMEOUT* = -0x00006800
  MBEDTLS_ERR_SSL_CLIENT_RECONNECT* = -0x00006780
  MBEDTLS_ERR_SSL_UNEXPECTED_RECORD* = -0x00006700
  MBEDTLS_ERR_SSL_NON_FATAL* = -0x00006680
  MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER* = -0x00006600
  MBEDTLS_ERR_SSL_CONTINUE_PROCESSING* = -0x00006580
  MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS* = -0x00006500
  MBEDTLS_ERR_SSL_EARLY_MESSAGE* = -0x00006480
  MBEDTLS_ERR_SSL_UNEXPECTED_CID* = -0x00006000
  MBEDTLS_ERR_SSL_VERSION_MISMATCH* = -0x00005F00
  MBEDTLS_ERR_SSL_BAD_CONFIG* = -0x00005E80
  MBEDTLS_SSL_TLS1_3_PSK_MODE_PURE* = 0
  MBEDTLS_SSL_TLS1_3_PSK_MODE_ECDHE* = 1
  MBEDTLS_SSL_IANA_TLS_GROUP_NONE* = 0
  MBEDTLS_SSL_IANA_TLS_GROUP_SECP192K1* = 0x00000012
  MBEDTLS_SSL_IANA_TLS_GROUP_SECP192R1* = 0x00000013
  MBEDTLS_SSL_IANA_TLS_GROUP_SECP224K1* = 0x00000014
  MBEDTLS_SSL_IANA_TLS_GROUP_SECP224R1* = 0x00000015
  MBEDTLS_SSL_IANA_TLS_GROUP_SECP256K1* = 0x00000016
  MBEDTLS_SSL_IANA_TLS_GROUP_SECP256R1* = 0x00000017
  MBEDTLS_SSL_IANA_TLS_GROUP_SECP384R1* = 0x00000018
  MBEDTLS_SSL_IANA_TLS_GROUP_SECP521R1* = 0x00000019
  MBEDTLS_SSL_IANA_TLS_GROUP_BP256R1* = 0x0000001A
  MBEDTLS_SSL_IANA_TLS_GROUP_BP384R1* = 0x0000001B
  MBEDTLS_SSL_IANA_TLS_GROUP_BP512R1* = 0x0000001C
  MBEDTLS_SSL_IANA_TLS_GROUP_X25519* = 0x0000001D
  MBEDTLS_SSL_IANA_TLS_GROUP_X448* = 0x0000001E
  MBEDTLS_SSL_IANA_TLS_GROUP_FFDHE2048* = 0x00000100
  MBEDTLS_SSL_IANA_TLS_GROUP_FFDHE3072* = 0x00000101
  MBEDTLS_SSL_IANA_TLS_GROUP_FFDHE4096* = 0x00000102
  MBEDTLS_SSL_IANA_TLS_GROUP_FFDHE6144* = 0x00000103
  MBEDTLS_SSL_IANA_TLS_GROUP_FFDHE8192* = 0x00000104
  MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK* = (1'u shl typeof(1'u)(0))
  MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL* = (1'u shl typeof(1'u)(1))
  MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL* = (1'u shl typeof(1'u)(2))
  MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_ALL* = (MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK or
      typeof(MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK)(
      MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL) or
      typeof(MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK)(
      MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL))
  MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ALL* = (MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK or
      typeof(MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK)(
      MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL))
  MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ALL* = (MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL or
      typeof(MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL)(
      MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL))
  MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_NONE* = (0)
  MBEDTLS_SSL_MAJOR_VERSION_3* = 3
  MBEDTLS_SSL_MINOR_VERSION_3* = 3
  MBEDTLS_SSL_MINOR_VERSION_4* = 4
  MBEDTLS_SSL_TRANSPORT_STREAM* = 0
  MBEDTLS_SSL_TRANSPORT_DATAGRAM* = 1
  MBEDTLS_SSL_MAX_HOST_NAME_LEN* = 255
  MBEDTLS_SSL_MAX_ALPN_NAME_LEN* = 255
  MBEDTLS_SSL_MAX_ALPN_LIST_LEN* = 65535
  MBEDTLS_SSL_MAX_FRAG_LEN_NONE* = 0
  MBEDTLS_SSL_MAX_FRAG_LEN_512* = 1
  MBEDTLS_SSL_MAX_FRAG_LEN_1024* = 2
  MBEDTLS_SSL_MAX_FRAG_LEN_2048* = 3
  MBEDTLS_SSL_MAX_FRAG_LEN_4096* = 4
  MBEDTLS_SSL_MAX_FRAG_LEN_INVALID* = 5
  MBEDTLS_SSL_IS_CLIENT* = 0
  MBEDTLS_SSL_IS_SERVER* = 1
  MBEDTLS_SSL_EXTENDED_MS_DISABLED* = 0
  MBEDTLS_SSL_EXTENDED_MS_ENABLED* = 1
  MBEDTLS_SSL_CID_DISABLED* = 0
  MBEDTLS_SSL_CID_ENABLED* = 1
  MBEDTLS_SSL_ETM_DISABLED* = 0
  MBEDTLS_SSL_ETM_ENABLED* = 1
  MBEDTLS_SSL_COMPRESS_NULL* = 0
  MBEDTLS_SSL_VERIFY_NONE* = 0
  MBEDTLS_SSL_VERIFY_OPTIONAL* = 1
  MBEDTLS_SSL_VERIFY_REQUIRED* = 2
  MBEDTLS_SSL_VERIFY_UNSET* = 3
  MBEDTLS_SSL_LEGACY_RENEGOTIATION* = 0
  MBEDTLS_SSL_SECURE_RENEGOTIATION* = 1
  MBEDTLS_SSL_RENEGOTIATION_DISABLED* = 0
  MBEDTLS_SSL_RENEGOTIATION_ENABLED* = 1
  MBEDTLS_SSL_ANTI_REPLAY_DISABLED* = 0
  MBEDTLS_SSL_ANTI_REPLAY_ENABLED* = 1
  MBEDTLS_SSL_RENEGOTIATION_NOT_ENFORCED* = -1
  MBEDTLS_SSL_RENEGO_MAX_RECORDS_DEFAULT* = 16
  MBEDTLS_SSL_LEGACY_NO_RENEGOTIATION* = 0
  MBEDTLS_SSL_LEGACY_ALLOW_RENEGOTIATION* = 1
  MBEDTLS_SSL_LEGACY_BREAK_HANDSHAKE* = 2
  MBEDTLS_SSL_TRUNC_HMAC_DISABLED* = 0
  MBEDTLS_SSL_TRUNC_HMAC_ENABLED* = 1
  MBEDTLS_SSL_TRUNCATED_HMAC_LEN* = 10
  MBEDTLS_SSL_SESSION_TICKETS_DISABLED* = 0
  MBEDTLS_SSL_SESSION_TICKETS_ENABLED* = 1
  MBEDTLS_SSL_PRESET_DEFAULT* = 0
  MBEDTLS_SSL_PRESET_SUITEB* = 2
  MBEDTLS_SSL_CERT_REQ_CA_LIST_ENABLED* = 1
  MBEDTLS_SSL_CERT_REQ_CA_LIST_DISABLED* = 0
  MBEDTLS_SSL_EARLY_DATA_DISABLED* = 0
  MBEDTLS_SSL_EARLY_DATA_ENABLED* = 1
  MBEDTLS_SSL_DTLS_SRTP_MKI_UNSUPPORTED* = 0
  MBEDTLS_SSL_DTLS_SRTP_MKI_SUPPORTED* = 1
  MBEDTLS_SSL_SRV_CIPHERSUITE_ORDER_CLIENT* = 1
  MBEDTLS_SSL_SRV_CIPHERSUITE_ORDER_SERVER* = 0
  MBEDTLS_SSL_DTLS_TIMEOUT_DFL_MIN* = 1000
  MBEDTLS_SSL_DTLS_TIMEOUT_DFL_MAX* = 60000
  MBEDTLS_SSL_IN_CONTENT_LEN* = 16384
  MBEDTLS_SSL_OUT_CONTENT_LEN* = 16384
  MBEDTLS_SSL_DTLS_MAX_BUFFERING* = 32768
  MBEDTLS_SSL_CID_IN_LEN_MAX* = 32
  MBEDTLS_SSL_CID_OUT_LEN_MAX* = 32
  MBEDTLS_SSL_CID_TLS1_3_PADDING_GRANULARITY* = 16
  MBEDTLS_SSL_VERIFY_DATA_MAX_LEN* = 12
  MBEDTLS_SSL_EMPTY_RENEGOTIATION_INFO* = 0x000000FF
  MBEDTLS_SSL_HASH_NONE* = 0
  MBEDTLS_SSL_HASH_MD5* = 1
  MBEDTLS_SSL_HASH_SHA1* = 2
  MBEDTLS_SSL_HASH_SHA224* = 3
  MBEDTLS_SSL_HASH_SHA256* = 4
  MBEDTLS_SSL_HASH_SHA384* = 5
  MBEDTLS_SSL_HASH_SHA512* = 6
  MBEDTLS_SSL_SIG_ANON* = 0
  MBEDTLS_SSL_SIG_RSA* = 1
  MBEDTLS_SSL_SIG_ECDSA* = 3
  MBEDTLS_TLS1_3_SIG_RSA_PKCS1_SHA256* = 0x00000401
  MBEDTLS_TLS1_3_SIG_RSA_PKCS1_SHA384* = 0x00000501
  MBEDTLS_TLS1_3_SIG_RSA_PKCS1_SHA512* = 0x00000601
  MBEDTLS_TLS1_3_SIG_ECDSA_SECP256R1_SHA256* = 0x00000403
  MBEDTLS_TLS1_3_SIG_ECDSA_SECP384R1_SHA384* = 0x00000503
  MBEDTLS_TLS1_3_SIG_ECDSA_SECP521R1_SHA512* = 0x00000603
  MBEDTLS_TLS1_3_SIG_RSA_PSS_RSAE_SHA256* = 0x00000804
  MBEDTLS_TLS1_3_SIG_RSA_PSS_RSAE_SHA384* = 0x00000805
  MBEDTLS_TLS1_3_SIG_RSA_PSS_RSAE_SHA512* = 0x00000806
  MBEDTLS_TLS1_3_SIG_ED25519* = 0x00000807
  MBEDTLS_TLS1_3_SIG_ED448* = 0x00000808
  MBEDTLS_TLS1_3_SIG_RSA_PSS_PSS_SHA256* = 0x00000809
  MBEDTLS_TLS1_3_SIG_RSA_PSS_PSS_SHA384* = 0x0000080A
  MBEDTLS_TLS1_3_SIG_RSA_PSS_PSS_SHA512* = 0x0000080B
  MBEDTLS_TLS1_3_SIG_RSA_PKCS1_SHA1* = 0x00000201
  MBEDTLS_TLS1_3_SIG_ECDSA_SHA1* = 0x00000203
  MBEDTLS_TLS1_3_SIG_NONE* = 0x00000000
  MBEDTLS_SSL_CERT_TYPE_RSA_SIGN* = 1
  MBEDTLS_SSL_CERT_TYPE_ECDSA_SIGN* = 64
  MBEDTLS_SSL_MSG_CHANGE_CIPHER_SPEC* = 20
  MBEDTLS_SSL_MSG_ALERT* = 21
  MBEDTLS_SSL_MSG_HANDSHAKE* = 22
  MBEDTLS_SSL_MSG_APPLICATION_DATA* = 23
  MBEDTLS_SSL_MSG_CID* = 25
  MBEDTLS_SSL_ALERT_LEVEL_WARNING* = 1
  MBEDTLS_SSL_ALERT_LEVEL_FATAL* = 2
  MBEDTLS_SSL_ALERT_MSG_CLOSE_NOTIFY* = 0
  MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE* = 10
  MBEDTLS_SSL_ALERT_MSG_BAD_RECORD_MAC* = 20
  MBEDTLS_SSL_ALERT_MSG_DECRYPTION_FAILED* = 21
  MBEDTLS_SSL_ALERT_MSG_RECORD_OVERFLOW* = 22
  MBEDTLS_SSL_ALERT_MSG_DECOMPRESSION_FAILURE* = 30
  MBEDTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE* = 40
  MBEDTLS_SSL_ALERT_MSG_NO_CERT* = 41
  MBEDTLS_SSL_ALERT_MSG_BAD_CERT* = 42
  MBEDTLS_SSL_ALERT_MSG_UNSUPPORTED_CERT* = 43
  MBEDTLS_SSL_ALERT_MSG_CERT_REVOKED* = 44
  MBEDTLS_SSL_ALERT_MSG_CERT_EXPIRED* = 45
  MBEDTLS_SSL_ALERT_MSG_CERT_UNKNOWN* = 46
  MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER* = 47
  MBEDTLS_SSL_ALERT_MSG_UNKNOWN_CA* = 48
  MBEDTLS_SSL_ALERT_MSG_ACCESS_DENIED* = 49
  MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR* = 50
  MBEDTLS_SSL_ALERT_MSG_DECRYPT_ERROR* = 51
  MBEDTLS_SSL_ALERT_MSG_EXPORT_RESTRICTION* = 60
  MBEDTLS_SSL_ALERT_MSG_PROTOCOL_VERSION* = 70
  MBEDTLS_SSL_ALERT_MSG_INSUFFICIENT_SECURITY* = 71
  MBEDTLS_SSL_ALERT_MSG_INTERNAL_ERROR* = 80
  MBEDTLS_SSL_ALERT_MSG_INAPROPRIATE_FALLBACK* = 86
  MBEDTLS_SSL_ALERT_MSG_USER_CANCELED* = 90
  MBEDTLS_SSL_ALERT_MSG_NO_RENEGOTIATION* = 100
  MBEDTLS_SSL_ALERT_MSG_MISSING_EXTENSION* = 109
  MBEDTLS_SSL_ALERT_MSG_UNSUPPORTED_EXT* = 110
  MBEDTLS_SSL_ALERT_MSG_UNRECOGNIZED_NAME* = 112
  MBEDTLS_SSL_ALERT_MSG_UNKNOWN_PSK_IDENTITY* = 115
  MBEDTLS_SSL_ALERT_MSG_CERT_REQUIRED* = 116
  MBEDTLS_SSL_ALERT_MSG_NO_APPLICATION_PROTOCOL* = 120
  MBEDTLS_SSL_HS_HELLO_REQUEST* = 0
  MBEDTLS_SSL_HS_CLIENT_HELLO* = 1
  MBEDTLS_SSL_HS_SERVER_HELLO* = 2
  MBEDTLS_SSL_HS_HELLO_VERIFY_REQUEST* = 3
  MBEDTLS_SSL_HS_NEW_SESSION_TICKET* = 4
  MBEDTLS_SSL_HS_END_OF_EARLY_DATA* = 5
  MBEDTLS_SSL_HS_ENCRYPTED_EXTENSIONS* = 8
  MBEDTLS_SSL_HS_CERTIFICATE* = 11
  MBEDTLS_SSL_HS_SERVER_KEY_EXCHANGE* = 12
  MBEDTLS_SSL_HS_CERTIFICATE_REQUEST* = 13
  MBEDTLS_SSL_HS_SERVER_HELLO_DONE* = 14
  MBEDTLS_SSL_HS_CERTIFICATE_VERIFY* = 15
  MBEDTLS_SSL_HS_CLIENT_KEY_EXCHANGE* = 16
  MBEDTLS_SSL_HS_FINISHED* = 20
  MBEDTLS_SSL_HS_MESSAGE_HASH* = 254
  MBEDTLS_TLS_EXT_SERVERNAME* = 0
  MBEDTLS_TLS_EXT_SERVERNAME_HOSTNAME* = 0
  MBEDTLS_TLS_EXT_MAX_FRAGMENT_LENGTH* = 1
  MBEDTLS_TLS_EXT_TRUNCATED_HMAC* = 4
  MBEDTLS_TLS_EXT_STATUS_REQUEST* = 5
  MBEDTLS_TLS_EXT_SUPPORTED_ELLIPTIC_CURVES* = 10
  MBEDTLS_TLS_EXT_SUPPORTED_GROUPS* = 10
  MBEDTLS_TLS_EXT_SUPPORTED_POINT_FORMATS* = 11
  MBEDTLS_TLS_EXT_SIG_ALG* = 13
  MBEDTLS_TLS_EXT_USE_SRTP* = 14
  MBEDTLS_TLS_EXT_HEARTBEAT* = 15
  MBEDTLS_TLS_EXT_ALPN* = 16
  MBEDTLS_TLS_EXT_SCT* = 18
  MBEDTLS_TLS_EXT_CLI_CERT_TYPE* = 19
  MBEDTLS_TLS_EXT_SERV_CERT_TYPE* = 20
  MBEDTLS_TLS_EXT_PADDING* = 21
  MBEDTLS_TLS_EXT_ENCRYPT_THEN_MAC* = 22
  MBEDTLS_TLS_EXT_EXTENDED_MASTER_SECRET* = 0x00000017
  MBEDTLS_TLS_EXT_RECORD_SIZE_LIMIT* = 28
  MBEDTLS_TLS_EXT_SESSION_TICKET* = 35
  MBEDTLS_TLS_EXT_PRE_SHARED_KEY* = 41
  MBEDTLS_TLS_EXT_EARLY_DATA* = 42
  MBEDTLS_TLS_EXT_SUPPORTED_VERSIONS* = 43
  MBEDTLS_TLS_EXT_COOKIE* = 44
  MBEDTLS_TLS_EXT_PSK_KEY_EXCHANGE_MODES* = 45
  MBEDTLS_TLS_EXT_CERT_AUTH* = 47
  MBEDTLS_TLS_EXT_OID_FILTERS* = 48
  MBEDTLS_TLS_EXT_POST_HANDSHAKE_AUTH* = 49
  MBEDTLS_TLS_EXT_SIG_ALG_CERT* = 50
  MBEDTLS_TLS_EXT_KEY_SHARE* = 51
  MBEDTLS_TLS_EXT_CID* = 54
  MBEDTLS_TLS_EXT_ECJPAKE_KKPP* = 256
  MBEDTLS_TLS_EXT_RENEGOTIATION_INFO* = 0x0000FF01
  MBEDTLS_PSK_MAX_LEN* = 32
  MBEDTLS_SSL_SEQUENCE_NUMBER_LEN* = 8
  MBEDTLS_SSL_HELLO_REQUEST* = (0).mbedtls_ssl_states
  MBEDTLS_SSL_CLIENT_HELLO* = (MBEDTLS_SSL_HELLO_REQUEST + 1).mbedtls_ssl_states
  MBEDTLS_SSL_SERVER_HELLO* = (MBEDTLS_SSL_CLIENT_HELLO + 1).mbedtls_ssl_states
  MBEDTLS_SSL_SERVER_CERTIFICATE* = (MBEDTLS_SSL_SERVER_HELLO + 1).mbedtls_ssl_states
  MBEDTLS_SSL_SERVER_KEY_EXCHANGE* = (MBEDTLS_SSL_SERVER_CERTIFICATE + 1).mbedtls_ssl_states
  MBEDTLS_SSL_CERTIFICATE_REQUEST* = (MBEDTLS_SSL_SERVER_KEY_EXCHANGE + 1).mbedtls_ssl_states
  MBEDTLS_SSL_SERVER_HELLO_DONE* = (MBEDTLS_SSL_CERTIFICATE_REQUEST + 1).mbedtls_ssl_states
  MBEDTLS_SSL_CLIENT_CERTIFICATE* = (MBEDTLS_SSL_SERVER_HELLO_DONE + 1).mbedtls_ssl_states
  MBEDTLS_SSL_CLIENT_KEY_EXCHANGE* = (MBEDTLS_SSL_CLIENT_CERTIFICATE + 1).mbedtls_ssl_states
  MBEDTLS_SSL_CERTIFICATE_VERIFY* = (MBEDTLS_SSL_CLIENT_KEY_EXCHANGE + 1).mbedtls_ssl_states
  MBEDTLS_SSL_CLIENT_CHANGE_CIPHER_SPEC* = (MBEDTLS_SSL_CERTIFICATE_VERIFY + 1).mbedtls_ssl_states
  MBEDTLS_SSL_CLIENT_FINISHED* = (MBEDTLS_SSL_CLIENT_CHANGE_CIPHER_SPEC + 1).mbedtls_ssl_states
  MBEDTLS_SSL_SERVER_CHANGE_CIPHER_SPEC* = (MBEDTLS_SSL_CLIENT_FINISHED + 1).mbedtls_ssl_states
  MBEDTLS_SSL_SERVER_FINISHED* = (MBEDTLS_SSL_SERVER_CHANGE_CIPHER_SPEC + 1).mbedtls_ssl_states
  MBEDTLS_SSL_FLUSH_BUFFERS* = (MBEDTLS_SSL_SERVER_FINISHED + 1).mbedtls_ssl_states
  MBEDTLS_SSL_HANDSHAKE_WRAPUP* = (MBEDTLS_SSL_FLUSH_BUFFERS + 1).mbedtls_ssl_states
  MBEDTLS_SSL_NEW_SESSION_TICKET* = (MBEDTLS_SSL_HANDSHAKE_WRAPUP + 1).mbedtls_ssl_states
  MBEDTLS_SSL_SERVER_HELLO_VERIFY_REQUEST_SENT* = (
      MBEDTLS_SSL_NEW_SESSION_TICKET + 1).mbedtls_ssl_states
  MBEDTLS_SSL_HELLO_RETRY_REQUEST* = (MBEDTLS_SSL_SERVER_HELLO_VERIFY_REQUEST_SENT +
      1).mbedtls_ssl_states
  MBEDTLS_SSL_ENCRYPTED_EXTENSIONS* = (MBEDTLS_SSL_HELLO_RETRY_REQUEST + 1).mbedtls_ssl_states
  MBEDTLS_SSL_END_OF_EARLY_DATA* = (MBEDTLS_SSL_ENCRYPTED_EXTENSIONS + 1).mbedtls_ssl_states
  MBEDTLS_SSL_CLIENT_CERTIFICATE_VERIFY* = (MBEDTLS_SSL_END_OF_EARLY_DATA + 1).mbedtls_ssl_states
  MBEDTLS_SSL_CLIENT_CCS_AFTER_SERVER_FINISHED* = (
      MBEDTLS_SSL_CLIENT_CERTIFICATE_VERIFY + 1).mbedtls_ssl_states
  MBEDTLS_SSL_CLIENT_CCS_BEFORE_2ND_CLIENT_HELLO* = (
      MBEDTLS_SSL_CLIENT_CCS_AFTER_SERVER_FINISHED + 1).mbedtls_ssl_states
  MBEDTLS_SSL_SERVER_CCS_AFTER_SERVER_HELLO* = (
      MBEDTLS_SSL_CLIENT_CCS_BEFORE_2ND_CLIENT_HELLO + 1).mbedtls_ssl_states
  MBEDTLS_SSL_CLIENT_CCS_AFTER_CLIENT_HELLO* = (
      MBEDTLS_SSL_SERVER_CCS_AFTER_SERVER_HELLO + 1).mbedtls_ssl_states
  MBEDTLS_SSL_SERVER_CCS_AFTER_HELLO_RETRY_REQUEST* = (
      MBEDTLS_SSL_CLIENT_CCS_AFTER_CLIENT_HELLO + 1).mbedtls_ssl_states
  MBEDTLS_SSL_HANDSHAKE_OVER* = (MBEDTLS_SSL_SERVER_CCS_AFTER_HELLO_RETRY_REQUEST +
      1).mbedtls_ssl_states
  MBEDTLS_SSL_TLS1_3_NEW_SESSION_TICKET* = (MBEDTLS_SSL_HANDSHAKE_OVER + 1).mbedtls_ssl_states
  MBEDTLS_SSL_TLS1_3_NEW_SESSION_TICKET_FLUSH* = (
      MBEDTLS_SSL_TLS1_3_NEW_SESSION_TICKET + 1).mbedtls_ssl_states
  MBEDTLS_SSL_VERSION_UNKNOWN* = (0).mbedtls_ssl_protocol_version
  MBEDTLS_SSL_VERSION_TLS1_2* = (0x00000303).mbedtls_ssl_protocol_version
  MBEDTLS_SSL_VERSION_TLS1_3* = (0x00000304).mbedtls_ssl_protocol_version
  MBEDTLS_SSL_TLS_PRF_NONE* = (0).mbedtls_tls_prf_types
  MBEDTLS_SSL_TLS_PRF_SHA384* = (MBEDTLS_SSL_TLS_PRF_NONE + 1).mbedtls_tls_prf_types
  MBEDTLS_SSL_TLS_PRF_SHA256* = (MBEDTLS_SSL_TLS_PRF_SHA384 + 1).mbedtls_tls_prf_types
  MBEDTLS_SSL_HKDF_EXPAND_SHA384* = (MBEDTLS_SSL_TLS_PRF_SHA256 + 1).mbedtls_tls_prf_types
  MBEDTLS_SSL_HKDF_EXPAND_SHA256* = (MBEDTLS_SSL_HKDF_EXPAND_SHA384 + 1).mbedtls_tls_prf_types
  MBEDTLS_SSL_KEY_EXPORT_TLS12_MASTER_SECRET* = (0).mbedtls_ssl_key_export_type
  MBEDTLS_SSL_UNEXPECTED_CID_IGNORE* = 0
  MBEDTLS_SSL_UNEXPECTED_CID_FAIL* = 1
type
  mbedtls_ssl_premaster_secret* {.union, bycopy.} = object
    u_pms_rsa*: array[48, byte]
    u_pms_dhm*: array[1024, byte]
    u_pms_ecdh*: array[(typeof(521)((521 + typeof(521)(7)) / typeof(521)(8))),
                       byte]
    u_pms_psk*: array[4 + typeof(4)(2 * typeof(4)(32)), byte]
    u_pms_dhe_psk*: array[4 + typeof(4)(1024) + typeof(4)(32), byte]
    uu_pms_rsa_psk*: array[52 + typeof(52)(32), byte]
    uu_pms_ecdhe_psk*: array[4 +
        typeof(4)((typeof(4)((521 + typeof(4)(7)) / typeof(4)(8)))) +
        typeof(4)(32), byte]

  mbedtls_ssl_send_t* = proc (ctx: pointer; buf: ptr byte; len: uint): cint {.
      cdecl.}
  mbedtls_ssl_recv_t* = proc (ctx: pointer; buf: ptr byte; len: uint): cint {.
      cdecl.}
  mbedtls_ssl_recv_timeout_t* = proc (ctx: pointer; buf: ptr byte; len: uint;
                                      timeout: uint32): cint {.cdecl.}
  mbedtls_ssl_set_timer_t* = proc (ctx: pointer; int_ms: uint32; fin_ms: uint32) {.
      cdecl.}
  mbedtls_ssl_get_timer_t* = proc (ctx: pointer): cint {.cdecl.}
  mbedtls_ssl_session* {.bycopy.} = object
    private_mfl_code*: byte
    private_exported*: byte
    private_tls_version*: mbedtls_ssl_protocol_version
    private_start*: mbedtls_time_t
    private_ciphersuite*: cint
    private_id_len*: uint
    private_id*: array[32, byte]
    private_master*: array[48, byte]
    private_peer_cert*: ptr mbedtls_x509_crt
    private_verify_result*: uint32
    private_ticket*: ptr byte
    private_ticket_len*: uint
    private_ticket_lifetime*: uint32
    private_encrypt_then_mac*: cint

  mbedtls_ssl_context* {.bycopy.} = object
    private_conf*: ptr mbedtls_ssl_config
    private_state*: cint
    private_renego_status*: cint
    private_renego_records_seen*: cint
    private_tls_version*: mbedtls_ssl_protocol_version
    private_badmac_seen*: cuint
    private_f_vrfy*: proc (a1: pointer; a2: ptr mbedtls_x509_crt; a3: cint;
                           a4: ptr uint32): cint {.cdecl.}
    private_p_vrfy*: pointer
    private_f_send*: ptr mbedtls_ssl_send_t
    private_f_recv*: ptr mbedtls_ssl_recv_t
    private_f_recv_timeout*: ptr mbedtls_ssl_recv_timeout_t
    private_p_bio*: pointer
    private_session_in*: ptr mbedtls_ssl_session
    private_session_out*: ptr mbedtls_ssl_session
    private_session*: ptr mbedtls_ssl_session
    private_session_negotiate*: ptr mbedtls_ssl_session
    private_handshake*: ptr mbedtls_ssl_handshake_params
    private_transform_in*: ptr mbedtls_ssl_transform
    private_transform_out*: ptr mbedtls_ssl_transform
    private_transform*: ptr mbedtls_ssl_transform
    private_transform_negotiate*: ptr mbedtls_ssl_transform
    private_p_timer*: pointer
    private_f_set_timer*: ptr mbedtls_ssl_set_timer_t
    private_f_get_timer*: ptr mbedtls_ssl_get_timer_t
    private_in_buf*: ptr byte
    private_in_ctr*: ptr byte
    private_in_hdr*: ptr byte
    private_in_cid*: ptr byte
    private_in_len*: ptr byte
    private_in_iv*: ptr byte
    private_in_msg*: ptr byte
    private_in_offt*: ptr byte
    private_in_msgtype*: cint
    private_in_msglen*: uint
    private_in_left*: uint
    private_in_epoch*: uint16
    private_next_record_offset*: uint
    private_in_window_top*: uint64
    private_in_window*: uint64
    private_in_hslen*: uint
    private_nb_zero*: cint
    private_keep_current_message*: cint
    private_send_alert*: byte
    private_alert_type*: byte
    private_alert_reason*: cint
    private_disable_datagram_packing*: uint8
    private_out_buf*: ptr byte
    private_out_ctr*: ptr byte
    private_out_hdr*: ptr byte
    private_out_cid*: ptr byte
    private_out_len*: ptr byte
    private_out_iv*: ptr byte
    private_out_msg*: ptr byte
    private_out_msgtype*: cint
    private_out_msglen*: uint
    private_out_left*: uint
    private_cur_out_ctr*: array[8, byte]
    private_mtu*: uint16
    private_hostname*: cstring
    private_alpn_chosen*: cstring
    private_cli_id*: ptr byte
    private_cli_id_len*: uint
    private_secure_renegotiation*: cint
    private_verify_data_len*: uint
    private_own_verify_data*: array[12, cchar]
    private_peer_verify_data*: array[12, cchar]
    private_own_cid*: array[32, byte]
    private_own_cid_len*: uint8
    private_negotiate_cid*: uint8
    private_f_export_keys*: ptr mbedtls_ssl_export_keys_t
    private_p_export_keys*: pointer
    private_user_data*: mbedtls_ssl_user_data_t

  mbedtls_ssl_config* {.bycopy.} = object
    private_max_tls_version*: mbedtls_ssl_protocol_version
    private_min_tls_version*: mbedtls_ssl_protocol_version
    private_endpoint*: uint8
    private_transport*: uint8
    private_authmode*: uint8
    private_allow_legacy_renegotiation*: uint8
    private_mfl_code*: uint8
    private_encrypt_then_mac*: uint8
    private_extended_ms*: uint8
    private_anti_replay*: uint8
    private_disable_renegotiation*: uint8
    private_session_tickets*: uint8
    private_cert_req_ca_list*: uint8
    private_respect_cli_pref*: uint8
    private_ignore_unexpected_cid*: uint8
    private_ciphersuite_list*: ptr cint
    private_f_dbg*: proc (a1: pointer; a2: cint; a3: cstring; a4: cint;
                          a5: cstring) {.cdecl.}
    private_p_dbg*: pointer
    private_f_rng*: proc (a1: pointer; a2: ptr byte; a3: uint): cint {.cdecl.}
    private_p_rng*: pointer
    private_f_get_cache*: ptr mbedtls_ssl_cache_get_t
    private_f_set_cache*: ptr mbedtls_ssl_cache_set_t
    private_p_cache*: pointer
    private_f_sni*: proc (a1: pointer; a2: ptr mbedtls_ssl_context;
                          a3: ptr byte; a4: uint): cint {.cdecl.}
    private_p_sni*: pointer
    private_f_vrfy*: proc (a1: pointer; a2: ptr mbedtls_x509_crt; a3: cint;
                           a4: ptr uint32): cint {.cdecl.}
    private_p_vrfy*: pointer
    private_f_psk*: proc (a1: pointer; a2: ptr mbedtls_ssl_context;
                          a3: ptr byte; a4: uint): cint {.cdecl.}
    private_p_psk*: pointer
    private_f_cookie_write*: proc (a1: pointer; a2: ptr ptr byte;
                                   a3: ptr byte; a4: ptr byte; a5: uint): cint {.
        cdecl.}
    private_f_cookie_check*: proc (a1: pointer; a2: ptr byte; a3: uint;
                                   a4: ptr byte; a5: uint): cint {.cdecl.}
    private_p_cookie*: pointer
    private_f_ticket_write*: proc (a1: pointer; a2: ptr mbedtls_ssl_session;
                                   a3: ptr byte; a4: ptr byte; a5: ptr uint;
                                   a6: ptr uint32): cint {.cdecl.}
    private_f_ticket_parse*: proc (a1: pointer; a2: ptr mbedtls_ssl_session;
                                   a3: ptr byte; a4: uint): cint {.cdecl.}
    private_p_ticket*: pointer
    private_cid_len*: uint
    private_cert_profile*: ptr mbedtls_x509_crt_profile
    private_key_cert*: ptr mbedtls_ssl_key_cert
    private_ca_chain*: ptr mbedtls_x509_crt
    private_ca_crl*: ptr mbedtls_x509_crl
    private_sig_hashes*: ptr cint
    private_sig_algs*: ptr uint16
    private_curve_list*: ptr mbedtls_ecp_group_id
    private_group_list*: ptr uint16
    private_dhm_P*: mbedtls_mpi
    private_dhm_G*: mbedtls_mpi
    private_psk*: ptr byte
    private_psk_len*: uint
    private_psk_identity*: ptr byte
    private_psk_identity_len*: uint
    private_alpn_list*: ptr cstring
    private_read_timeout*: uint32
    private_hs_timeout_min*: uint32
    private_hs_timeout_max*: uint32
    private_renego_max_records*: cint
    private_renego_period*: array[8, byte]
    private_badmac_limit*: cuint
    private_dhm_min_bitlen*: cuint
    private_user_data*: mbedtls_ssl_user_data_t
    private_f_cert_cb*: mbedtls_ssl_hs_cb_t
    private_dn_hints*: ptr mbedtls_x509_crt

  mbedtls_ssl_transform* {.incompleteStruct.} = object
  mbedtls_ssl_handshake_params* {.incompleteStruct.} = object
  mbedtls_ssl_sig_hash_set_t* {.incompleteStruct.} = object
  mbedtls_ssl_key_cert* {.incompleteStruct.} = object
  mbedtls_ssl_flight_item* {.incompleteStruct.} = object
  mbedtls_ssl_cache_get_t* = proc (data: pointer; session_id: ptr byte;
                                   session_id_len: uint;
                                   session: ptr mbedtls_ssl_session): cint {.
      cdecl.}
  mbedtls_ssl_cache_set_t* = proc (data: pointer; session_id: ptr byte;
                                   session_id_len: uint;
                                   session: ptr mbedtls_ssl_session): cint {.
      cdecl.}
  mbedtls_ssl_tls13_application_secrets* {.bycopy.} = object
    client_application_traffic_secret_N*: array[64, byte]
    server_application_traffic_secret_N*: array[64, byte]
    exporter_master_secret*: array[64, byte]
    resumption_master_secret*: array[64, byte]

  mbedtls_ssl_export_keys_t* = proc (p_expkey: pointer;
                                     `type`: mbedtls_ssl_key_export_type;
                                     secret: ptr byte; secret_len: uint;
                                     client_random: array[32, byte];
                                     server_random: array[32, byte];
                                     tls_prf_type: mbedtls_tls_prf_types) {.
      cdecl.}
  mbedtls_ssl_hs_cb_t* = proc (ssl: ptr mbedtls_ssl_context): cint {.cdecl.}
  mbedtls_ssl_user_data_t* {.union, bycopy.} = object
    n*: ptr uint
    p*: pointer

  mbedtls_ssl_ticket_write_t* = proc (p_ticket: pointer;
                                      session: ptr mbedtls_ssl_session;
                                      start: ptr byte; `end`: ptr byte;
                                      tlen: ptr uint; lifetime: ptr uint32): cint {.
      cdecl.}
  mbedtls_ssl_ticket_parse_t* = proc (p_ticket: pointer;
                                      session: ptr mbedtls_ssl_session;
                                      buf: ptr byte; len: uint): cint {.cdecl.}
  mbedtls_ssl_cookie_write_t* = proc (ctx: pointer; p: ptr ptr byte;
                                      `end`: ptr byte; info: ptr byte;
                                      ilen: uint): cint {.cdecl.}
  mbedtls_ssl_cookie_check_t* = proc (ctx: pointer; cookie: ptr byte;
                                      clen: uint; info: ptr byte; ilen: uint): cint {.
      cdecl.}
proc mbedtls_ssl_get_ciphersuite_name*(ciphersuite_id: cint): cstring {.importc,
    cdecl.}
proc mbedtls_ssl_get_ciphersuite_id*(ciphersuite_name: cstring): cint {.importc,
    cdecl.}
proc mbedtls_ssl_init*(ssl: ptr mbedtls_ssl_context) {.importc, cdecl.}
proc mbedtls_ssl_setup*(ssl: ptr mbedtls_ssl_context;
                        conf: ptr mbedtls_ssl_config): cint {.importc, cdecl.}
proc mbedtls_ssl_session_reset*(ssl: ptr mbedtls_ssl_context): cint {.importc,
    cdecl.}
proc mbedtls_ssl_conf_endpoint*(conf: ptr mbedtls_ssl_config; endpoint: cint) {.
    importc, cdecl.}
proc mbedtls_ssl_conf_transport*(conf: ptr mbedtls_ssl_config; transport: cint) {.
    importc, cdecl.}
proc mbedtls_ssl_conf_authmode*(conf: ptr mbedtls_ssl_config; authmode: cint) {.
    importc, cdecl.}
proc mbedtls_ssl_conf_verify*(conf: ptr mbedtls_ssl_config; f_vrfy: proc (
    a1: pointer; a2: ptr mbedtls_x509_crt; a3: cint; a4: ptr uint32): cint {.
    cdecl.}; p_vrfy: pointer) {.importc, cdecl.}
proc mbedtls_ssl_conf_rng*(conf: ptr mbedtls_ssl_config; f_rng: proc (
    a1: pointer; a2: ptr byte; a3: uint): cint {.cdecl.}; p_rng: pointer) {.
    importc, cdecl.}
proc mbedtls_ssl_conf_dbg*(conf: ptr mbedtls_ssl_config; f_dbg: proc (
    a1: pointer; a2: cint; a3: cstring; a4: cint; a5: cstring) {.cdecl.};
                           p_dbg: pointer) {.importc, cdecl.}
proc mbedtls_ssl_set_bio*(ssl: ptr mbedtls_ssl_context; p_bio: pointer;
                          f_send: ptr mbedtls_ssl_send_t;
                          f_recv: ptr mbedtls_ssl_recv_t;
                          f_recv_timeout: ptr mbedtls_ssl_recv_timeout_t) {.
    importc, cdecl.}
proc mbedtls_ssl_set_cid*(ssl: ptr mbedtls_ssl_context; enable: cint;
                          own_cid: ptr byte; own_cid_len: uint): cint {.
    importc, cdecl.}
proc mbedtls_ssl_get_own_cid*(ssl: ptr mbedtls_ssl_context; enabled: ptr cint;
                              own_cid: array[32, byte]; own_cid_len: ptr uint): cint {.
    importc, cdecl.}
proc mbedtls_ssl_get_peer_cid*(ssl: ptr mbedtls_ssl_context; enabled: ptr cint;
                               peer_cid: array[32, byte];
                               peer_cid_len: ptr uint): cint {.importc, cdecl.}
proc mbedtls_ssl_set_mtu*(ssl: ptr mbedtls_ssl_context; mtu: uint16) {.importc,
    cdecl.}
proc mbedtls_ssl_set_verify*(ssl: ptr mbedtls_ssl_context; f_vrfy: proc (
    a1: pointer; a2: ptr mbedtls_x509_crt; a3: cint; a4: ptr uint32): cint {.
    cdecl.}; p_vrfy: pointer) {.importc, cdecl.}
proc mbedtls_ssl_conf_read_timeout*(conf: ptr mbedtls_ssl_config;
                                    timeout: uint32) {.importc, cdecl.}
proc mbedtls_ssl_check_record*(ssl: ptr mbedtls_ssl_context; buf: ptr byte;
                               buflen: uint): cint {.importc, cdecl.}
proc mbedtls_ssl_set_timer_cb*(ssl: ptr mbedtls_ssl_context; p_timer: pointer;
                               f_set_timer: ptr mbedtls_ssl_set_timer_t;
                               f_get_timer: ptr mbedtls_ssl_get_timer_t) {.
    importc, cdecl.}
proc mbedtls_ssl_conf_session_tickets_cb*(conf: ptr mbedtls_ssl_config;
    f_ticket_write: ptr mbedtls_ssl_ticket_write_t;
    f_ticket_parse: ptr mbedtls_ssl_ticket_parse_t; p_ticket: pointer) {.
    importc, cdecl.}
proc mbedtls_ssl_set_export_keys_cb*(ssl: ptr mbedtls_ssl_context; f_export_keys: ptr mbedtls_ssl_export_keys_t;
                                     p_export_keys: pointer) {.importc, cdecl.}
proc mbedtls_ssl_conf_dtls_cookies*(conf: ptr mbedtls_ssl_config; f_cookie_write: ptr mbedtls_ssl_cookie_write_t;
    f_cookie_check: ptr mbedtls_ssl_cookie_check_t; p_cookie: pointer) {.
    importc, cdecl.}
proc mbedtls_ssl_set_client_transport_id*(ssl: ptr mbedtls_ssl_context;
    info: ptr byte; ilen: uint): cint {.importc, cdecl.}
proc mbedtls_ssl_conf_dtls_anti_replay*(conf: ptr mbedtls_ssl_config;
                                        mode: cchar) {.importc, cdecl.}
proc mbedtls_ssl_conf_dtls_badmac_limit*(conf: ptr mbedtls_ssl_config;
    limit: cuint) {.importc, cdecl.}
proc mbedtls_ssl_set_datagram_packing*(ssl: ptr mbedtls_ssl_context;
                                       allow_packing: cuint) {.importc, cdecl.}
proc mbedtls_ssl_conf_handshake_timeout*(conf: ptr mbedtls_ssl_config;
    min: uint32; max: uint32) {.importc, cdecl.}
proc mbedtls_ssl_conf_session_cache*(conf: ptr mbedtls_ssl_config;
                                     p_cache: pointer;
                                     f_get_cache: ptr mbedtls_ssl_cache_get_t;
                                     f_set_cache: ptr mbedtls_ssl_cache_set_t) {.
    importc, cdecl.}
proc mbedtls_ssl_set_session*(ssl: ptr mbedtls_ssl_context;
                              session: ptr mbedtls_ssl_session): cint {.importc,
    cdecl.}
proc mbedtls_ssl_session_load*(session: ptr mbedtls_ssl_session;
                               buf: ptr byte; len: uint): cint {.importc,
    cdecl.}
proc mbedtls_ssl_session_save*(session: ptr mbedtls_ssl_session;
                               buf: ptr byte; buf_len: uint; olen: ptr uint): cint {.
    importc, cdecl.}
proc mbedtls_ssl_conf_ciphersuites*(conf: ptr mbedtls_ssl_config;
                                    ciphersuites: ptr cint) {.importc, cdecl.}
proc mbedtls_ssl_conf_cid*(conf: ptr mbedtls_ssl_config; len: uint;
                           ignore_other_cids: cint): cint {.importc, cdecl.}
proc mbedtls_ssl_conf_cert_profile*(conf: ptr mbedtls_ssl_config;
                                    profile: ptr mbedtls_x509_crt_profile) {.
    importc, cdecl.}
proc mbedtls_ssl_conf_ca_chain*(conf: ptr mbedtls_ssl_config;
                                ca_chain: ptr mbedtls_x509_crt;
                                ca_crl: ptr mbedtls_x509_crl) {.importc, cdecl.}
proc mbedtls_ssl_conf_own_cert*(conf: ptr mbedtls_ssl_config;
                                own_cert: ptr mbedtls_x509_crt;
                                pk_key: ptr mbedtls_pk_context): cint {.importc,
    cdecl.}
proc mbedtls_ssl_conf_psk*(conf: ptr mbedtls_ssl_config; psk: ptr byte;
                           psk_len: uint; psk_identity: ptr byte;
                           psk_identity_len: uint): cint {.importc, cdecl.}
proc mbedtls_ssl_set_hs_psk*(ssl: ptr mbedtls_ssl_context; psk: ptr byte;
                             psk_len: uint): cint {.importc, cdecl.}
proc mbedtls_ssl_conf_psk_cb*(conf: ptr mbedtls_ssl_config; f_psk: proc (
    a1: pointer; a2: ptr mbedtls_ssl_context; a3: ptr byte; a4: uint): cint {.
    cdecl.}; p_psk: pointer) {.importc, cdecl.}
proc mbedtls_ssl_conf_dh_param_bin*(conf: ptr mbedtls_ssl_config;
                                    dhm_P: ptr byte; P_len: uint;
                                    dhm_G: ptr byte; G_len: uint): cint {.
    importc, cdecl.}
proc mbedtls_ssl_conf_dh_param_ctx*(conf: ptr mbedtls_ssl_config;
                                    dhm_ctx: ptr mbedtls_dhm_context): cint {.
    importc, cdecl.}
proc mbedtls_ssl_conf_dhm_min_bitlen*(conf: ptr mbedtls_ssl_config;
                                      bitlen: cuint) {.importc, cdecl.}
proc mbedtls_ssl_conf_curves*(conf: ptr mbedtls_ssl_config;
                              curves: ptr mbedtls_ecp_group_id) {.importc, cdecl.}
proc mbedtls_ssl_conf_groups*(conf: ptr mbedtls_ssl_config; groups: ptr uint16) {.
    importc, cdecl.}
proc mbedtls_ssl_conf_sig_hashes*(conf: ptr mbedtls_ssl_config; hashes: ptr cint) {.
    importc, cdecl.}
proc mbedtls_ssl_conf_sig_algs*(conf: ptr mbedtls_ssl_config;
                                sig_algs: ptr uint16) {.importc, cdecl.}
proc mbedtls_ssl_set_hostname*(ssl: ptr mbedtls_ssl_context; hostname: cstring): cint {.
    importc, cdecl.}
proc mbedtls_ssl_get_hs_sni*(ssl: ptr mbedtls_ssl_context; name_len: ptr uint): ptr byte {.
    importc, cdecl.}
proc mbedtls_ssl_set_hs_own_cert*(ssl: ptr mbedtls_ssl_context;
                                  own_cert: ptr mbedtls_x509_crt;
                                  pk_key: ptr mbedtls_pk_context): cint {.
    importc, cdecl.}
proc mbedtls_ssl_set_hs_ca_chain*(ssl: ptr mbedtls_ssl_context;
                                  ca_chain: ptr mbedtls_x509_crt;
                                  ca_crl: ptr mbedtls_x509_crl) {.importc, cdecl.}
proc mbedtls_ssl_set_hs_dn_hints*(ssl: ptr mbedtls_ssl_context;
                                  crt: ptr mbedtls_x509_crt) {.importc, cdecl.}
proc mbedtls_ssl_set_hs_authmode*(ssl: ptr mbedtls_ssl_context; authmode: cint) {.
    importc, cdecl.}
proc mbedtls_ssl_conf_sni*(conf: ptr mbedtls_ssl_config; f_sni: proc (
    a1: pointer; a2: ptr mbedtls_ssl_context; a3: ptr byte; a4: uint): cint {.
    cdecl.}; p_sni: pointer) {.importc, cdecl.}
proc mbedtls_ssl_conf_alpn_protocols*(conf: ptr mbedtls_ssl_config;
                                      protos: ptr cstring): cint {.importc,
    cdecl.}
proc mbedtls_ssl_get_alpn_protocol*(ssl: ptr mbedtls_ssl_context): cstring {.
    importc, cdecl.}
proc mbedtls_ssl_conf_max_version*(conf: ptr mbedtls_ssl_config; major: cint;
                                   minor: cint) {.importc, cdecl.}
proc mbedtls_ssl_conf_min_version*(conf: ptr mbedtls_ssl_config; major: cint;
                                   minor: cint) {.importc, cdecl.}
proc mbedtls_ssl_conf_encrypt_then_mac*(conf: ptr mbedtls_ssl_config; etm: cchar) {.
    importc, cdecl.}
proc mbedtls_ssl_conf_extended_master_secret*(conf: ptr mbedtls_ssl_config;
    ems: cchar) {.importc, cdecl.}
proc mbedtls_ssl_conf_cert_req_ca_list*(conf: ptr mbedtls_ssl_config;
                                        cert_req_ca_list: cchar) {.importc,
    cdecl.}
proc mbedtls_ssl_conf_max_frag_len*(conf: ptr mbedtls_ssl_config;
                                    mfl_code: byte): cint {.importc, cdecl.}
proc mbedtls_ssl_conf_preference_order*(conf: ptr mbedtls_ssl_config;
                                        order: cint) {.importc, cdecl.}
proc mbedtls_ssl_conf_session_tickets*(conf: ptr mbedtls_ssl_config;
                                       use_tickets: cint) {.importc, cdecl.}
proc mbedtls_ssl_conf_renegotiation*(conf: ptr mbedtls_ssl_config;
                                     renegotiation: cint) {.importc, cdecl.}
proc mbedtls_ssl_conf_legacy_renegotiation*(conf: ptr mbedtls_ssl_config;
    allow_legacy: cint) {.importc, cdecl.}
proc mbedtls_ssl_conf_renegotiation_enforced*(conf: ptr mbedtls_ssl_config;
    max_records: cint) {.importc, cdecl.}
proc mbedtls_ssl_conf_renegotiation_period*(conf: ptr mbedtls_ssl_config;
    period: array[8, byte]) {.importc, cdecl.}
proc mbedtls_ssl_check_pending*(ssl: ptr mbedtls_ssl_context): cint {.importc,
    cdecl.}
proc mbedtls_ssl_get_bytes_avail*(ssl: ptr mbedtls_ssl_context): uint {.importc,
    cdecl.}
proc mbedtls_ssl_get_verify_result*(ssl: ptr mbedtls_ssl_context): uint32 {.
    importc, cdecl.}
proc mbedtls_ssl_get_ciphersuite_id_from_ssl*(ssl: ptr mbedtls_ssl_context): cint {.
    importc, cdecl.}
proc mbedtls_ssl_get_ciphersuite*(ssl: ptr mbedtls_ssl_context): cstring {.
    importc, cdecl.}
proc mbedtls_ssl_get_version*(ssl: ptr mbedtls_ssl_context): cstring {.importc,
    cdecl.}
proc mbedtls_ssl_get_record_expansion*(ssl: ptr mbedtls_ssl_context): cint {.
    importc, cdecl.}
proc mbedtls_ssl_get_max_out_record_payload*(ssl: ptr mbedtls_ssl_context): cint {.
    importc, cdecl.}
proc mbedtls_ssl_get_max_in_record_payload*(ssl: ptr mbedtls_ssl_context): cint {.
    importc, cdecl.}
proc mbedtls_ssl_get_peer_cert*(ssl: ptr mbedtls_ssl_context): ptr mbedtls_x509_crt {.
    importc, cdecl.}
proc mbedtls_ssl_get_session*(ssl: ptr mbedtls_ssl_context;
                              session: ptr mbedtls_ssl_session): cint {.importc,
    cdecl.}
proc mbedtls_ssl_handshake*(ssl: ptr mbedtls_ssl_context): cint {.importc, cdecl.}
proc mbedtls_ssl_handshake_step*(ssl: ptr mbedtls_ssl_context): cint {.importc,
    cdecl.}
proc mbedtls_ssl_renegotiate*(ssl: ptr mbedtls_ssl_context): cint {.importc,
    cdecl.}
proc mbedtls_ssl_read*(ssl: ptr mbedtls_ssl_context; buf: ptr byte; len: uint): cint {.
    importc, cdecl.}
proc mbedtls_ssl_write*(ssl: ptr mbedtls_ssl_context; buf: ptr byte; len: uint): cint {.
    importc, cdecl.}
proc mbedtls_ssl_send_alert_message*(ssl: ptr mbedtls_ssl_context;
                                     level: byte; message: byte): cint {.
    importc, cdecl.}
proc mbedtls_ssl_close_notify*(ssl: ptr mbedtls_ssl_context): cint {.importc,
    cdecl.}
proc mbedtls_ssl_free*(ssl: ptr mbedtls_ssl_context) {.importc, cdecl.}
proc mbedtls_ssl_context_save*(ssl: ptr mbedtls_ssl_context; buf: ptr byte;
                               buf_len: uint; olen: ptr uint): cint {.importc,
    cdecl.}
proc mbedtls_ssl_context_load*(ssl: ptr mbedtls_ssl_context; buf: ptr byte;
                               len: uint): cint {.importc, cdecl.}
proc mbedtls_ssl_config_init*(conf: ptr mbedtls_ssl_config) {.importc, cdecl.}
proc mbedtls_ssl_config_defaults*(conf: ptr mbedtls_ssl_config; endpoint: cint;
                                  transport: cint; preset: cint): cint {.
    importc, cdecl.}
proc mbedtls_ssl_config_free*(conf: ptr mbedtls_ssl_config) {.importc, cdecl.}
proc mbedtls_ssl_session_init*(session: ptr mbedtls_ssl_session) {.importc,
    cdecl.}
proc mbedtls_ssl_session_free*(session: ptr mbedtls_ssl_session) {.importc,
    cdecl.}
proc mbedtls_ssl_tls_prf*(prf: mbedtls_tls_prf_types; secret: ptr byte;
                          slen: uint; label: cstring; random: ptr byte;
                          rlen: uint; dstbuf: ptr byte; dlen: uint): cint {.
    importc, cdecl.}
{.pop.}
