import "csources"
import "asn1"
import "pk"
import "md"
import "ecp"
import "cipher"

# const 'MBEDTLS_OID_RSA_COMPANY' has unsupported value 'MBEDTLS_OID_ISO_MEMBER_BODIES MBEDTLS_OID_COUNTRY_US MBEDTLS_OID_ORG_RSA_DATA_SECURITY'
# const 'MBEDTLS_OID_ANSI_X9_62' has unsupported value 'MBEDTLS_OID_ISO_MEMBER_BODIES MBEDTLS_OID_COUNTRY_US MBEDTLS_OID_ORG_ANSI_X9_62'
# const 'MBEDTLS_OID_OIW_SECSIG' has unsupported value 'MBEDTLS_OID_ORG_OIW "\x03"'
# const 'MBEDTLS_OID_OIW_SECSIG_ALG' has unsupported value 'MBEDTLS_OID_OIW_SECSIG "\x02"'
# const 'MBEDTLS_OID_OIW_SECSIG_SHA1' has unsupported value 'MBEDTLS_OID_OIW_SECSIG_ALG "\x1a"'
# const 'MBEDTLS_OID_CERTICOM' has unsupported value 'MBEDTLS_OID_ISO_IDENTIFIED_ORG MBEDTLS_OID_ORG_CERTICOM'
# const 'MBEDTLS_OID_TELETRUST' has unsupported value 'MBEDTLS_OID_ISO_IDENTIFIED_ORG MBEDTLS_OID_ORG_TELETRUST'
# const 'MBEDTLS_OID_ISO_ITU_US_ORG' has unsupported value 'MBEDTLS_OID_ISO_ITU_COUNTRY MBEDTLS_OID_COUNTRY_US MBEDTLS_OID_ORGANIZATION'
# const 'MBEDTLS_OID_GOV' has unsupported value 'MBEDTLS_OID_ISO_ITU_US_ORG MBEDTLS_OID_ORG_GOV'
# const 'MBEDTLS_OID_NETSCAPE' has unsupported value 'MBEDTLS_OID_ISO_ITU_US_ORG MBEDTLS_OID_ORG_NETSCAPE'
# const 'MBEDTLS_OID_ID_CE' has unsupported value 'MBEDTLS_OID_ISO_CCITT_DS "\x1D"'
# const 'MBEDTLS_OID_NIST_ALG' has unsupported value 'MBEDTLS_OID_GOV "\x03\x04"'
# const 'MBEDTLS_OID_INTERNET' has unsupported value 'MBEDTLS_OID_ISO_IDENTIFIED_ORG MBEDTLS_OID_ORG_DOD "\x01"'
# const 'MBEDTLS_OID_PKIX' has unsupported value 'MBEDTLS_OID_INTERNET "\x05\x05\x07"'
# const 'MBEDTLS_OID_AT' has unsupported value 'MBEDTLS_OID_ISO_CCITT_DS "\x04"'
# const 'MBEDTLS_OID_AT_CN' has unsupported value 'MBEDTLS_OID_AT "\x03"'
# const 'MBEDTLS_OID_AT_SUR_NAME' has unsupported value 'MBEDTLS_OID_AT "\x04"'
# const 'MBEDTLS_OID_AT_SERIAL_NUMBER' has unsupported value 'MBEDTLS_OID_AT "\x05"'
# const 'MBEDTLS_OID_AT_COUNTRY' has unsupported value 'MBEDTLS_OID_AT "\x06"'
# const 'MBEDTLS_OID_AT_LOCALITY' has unsupported value 'MBEDTLS_OID_AT "\x07"'
# const 'MBEDTLS_OID_AT_STATE' has unsupported value 'MBEDTLS_OID_AT "\x08"'
# const 'MBEDTLS_OID_AT_ORGANIZATION' has unsupported value 'MBEDTLS_OID_AT "\x0A"'
# const 'MBEDTLS_OID_AT_ORG_UNIT' has unsupported value 'MBEDTLS_OID_AT "\x0B"'
# const 'MBEDTLS_OID_AT_TITLE' has unsupported value 'MBEDTLS_OID_AT "\x0C"'
# const 'MBEDTLS_OID_AT_POSTAL_ADDRESS' has unsupported value 'MBEDTLS_OID_AT "\x10"'
# const 'MBEDTLS_OID_AT_POSTAL_CODE' has unsupported value 'MBEDTLS_OID_AT "\x11"'
# const 'MBEDTLS_OID_AT_GIVEN_NAME' has unsupported value 'MBEDTLS_OID_AT "\x2A"'
# const 'MBEDTLS_OID_AT_INITIALS' has unsupported value 'MBEDTLS_OID_AT "\x2B"'
# const 'MBEDTLS_OID_AT_GENERATION_QUALIFIER' has unsupported value 'MBEDTLS_OID_AT "\x2C"'
# const 'MBEDTLS_OID_AT_UNIQUE_IDENTIFIER' has unsupported value 'MBEDTLS_OID_AT "\x2D"'
# const 'MBEDTLS_OID_AT_DN_QUALIFIER' has unsupported value 'MBEDTLS_OID_AT "\x2E"'
# const 'MBEDTLS_OID_AT_PSEUDONYM' has unsupported value 'MBEDTLS_OID_AT "\x41"'
# const 'MBEDTLS_OID_AUTHORITY_KEY_IDENTIFIER' has unsupported value 'MBEDTLS_OID_ID_CE "\x23"'
# const 'MBEDTLS_OID_SUBJECT_KEY_IDENTIFIER' has unsupported value 'MBEDTLS_OID_ID_CE "\x0E"'
# const 'MBEDTLS_OID_KEY_USAGE' has unsupported value 'MBEDTLS_OID_ID_CE "\x0F"'
# const 'MBEDTLS_OID_CERTIFICATE_POLICIES' has unsupported value 'MBEDTLS_OID_ID_CE "\x20"'
# const 'MBEDTLS_OID_POLICY_MAPPINGS' has unsupported value 'MBEDTLS_OID_ID_CE "\x21"'
# const 'MBEDTLS_OID_SUBJECT_ALT_NAME' has unsupported value 'MBEDTLS_OID_ID_CE "\x11"'
# const 'MBEDTLS_OID_ISSUER_ALT_NAME' has unsupported value 'MBEDTLS_OID_ID_CE "\x12"'
# const 'MBEDTLS_OID_SUBJECT_DIRECTORY_ATTRS' has unsupported value 'MBEDTLS_OID_ID_CE "\x09"'
# const 'MBEDTLS_OID_BASIC_CONSTRAINTS' has unsupported value 'MBEDTLS_OID_ID_CE "\x13"'
# const 'MBEDTLS_OID_NAME_CONSTRAINTS' has unsupported value 'MBEDTLS_OID_ID_CE "\x1E"'
# const 'MBEDTLS_OID_POLICY_CONSTRAINTS' has unsupported value 'MBEDTLS_OID_ID_CE "\x24"'
# const 'MBEDTLS_OID_EXTENDED_KEY_USAGE' has unsupported value 'MBEDTLS_OID_ID_CE "\x25"'
# const 'MBEDTLS_OID_CRL_DISTRIBUTION_POINTS' has unsupported value 'MBEDTLS_OID_ID_CE "\x1F"'
# const 'MBEDTLS_OID_INIHIBIT_ANYPOLICY' has unsupported value 'MBEDTLS_OID_ID_CE "\x36"'
# const 'MBEDTLS_OID_FRESHEST_CRL' has unsupported value 'MBEDTLS_OID_ID_CE "\x2E"'
# const 'MBEDTLS_OID_ANY_POLICY' has unsupported value 'MBEDTLS_OID_CERTIFICATE_POLICIES "\x00"'
# const 'MBEDTLS_OID_NS_CERT' has unsupported value 'MBEDTLS_OID_NETSCAPE "\x01"'
# const 'MBEDTLS_OID_NS_CERT_TYPE' has unsupported value 'MBEDTLS_OID_NS_CERT "\x01"'
# const 'MBEDTLS_OID_NS_BASE_URL' has unsupported value 'MBEDTLS_OID_NS_CERT "\x02"'
# const 'MBEDTLS_OID_NS_REVOCATION_URL' has unsupported value 'MBEDTLS_OID_NS_CERT "\x03"'
# const 'MBEDTLS_OID_NS_CA_REVOCATION_URL' has unsupported value 'MBEDTLS_OID_NS_CERT "\x04"'
# const 'MBEDTLS_OID_NS_RENEWAL_URL' has unsupported value 'MBEDTLS_OID_NS_CERT "\x07"'
# const 'MBEDTLS_OID_NS_CA_POLICY_URL' has unsupported value 'MBEDTLS_OID_NS_CERT "\x08"'
# const 'MBEDTLS_OID_NS_SSL_SERVER_NAME' has unsupported value 'MBEDTLS_OID_NS_CERT "\x0C"'
# const 'MBEDTLS_OID_NS_COMMENT' has unsupported value 'MBEDTLS_OID_NS_CERT "\x0D"'
# const 'MBEDTLS_OID_NS_DATA_TYPE' has unsupported value 'MBEDTLS_OID_NETSCAPE "\x02"'
# const 'MBEDTLS_OID_NS_CERT_SEQUENCE' has unsupported value 'MBEDTLS_OID_NS_DATA_TYPE "\x05"'
# const 'MBEDTLS_OID_PRIVATE_KEY_USAGE_PERIOD' has unsupported value 'MBEDTLS_OID_ID_CE "\x10"'
# const 'MBEDTLS_OID_CRL_NUMBER' has unsupported value 'MBEDTLS_OID_ID_CE "\x14"'
# const 'MBEDTLS_OID_ANY_EXTENDED_KEY_USAGE' has unsupported value 'MBEDTLS_OID_EXTENDED_KEY_USAGE "\x00"'
# const 'MBEDTLS_OID_KP' has unsupported value 'MBEDTLS_OID_PKIX "\x03"'
# const 'MBEDTLS_OID_SERVER_AUTH' has unsupported value 'MBEDTLS_OID_KP "\x01"'
# const 'MBEDTLS_OID_CLIENT_AUTH' has unsupported value 'MBEDTLS_OID_KP "\x02"'
# const 'MBEDTLS_OID_CODE_SIGNING' has unsupported value 'MBEDTLS_OID_KP "\x03"'
# const 'MBEDTLS_OID_EMAIL_PROTECTION' has unsupported value 'MBEDTLS_OID_KP "\x04"'
# const 'MBEDTLS_OID_TIME_STAMPING' has unsupported value 'MBEDTLS_OID_KP "\x08"'
# const 'MBEDTLS_OID_OCSP_SIGNING' has unsupported value 'MBEDTLS_OID_KP "\x09"'
# const 'MBEDTLS_OID_WISUN_FAN' has unsupported value 'MBEDTLS_OID_INTERNET "\x04\x01\x82\xe4\x25\x01"'
# const 'MBEDTLS_OID_ON' has unsupported value 'MBEDTLS_OID_PKIX "\x08"'
# const 'MBEDTLS_OID_ON_HW_MODULE_NAME' has unsupported value 'MBEDTLS_OID_ON "\x04"'
# const 'MBEDTLS_OID_PKCS' has unsupported value 'MBEDTLS_OID_RSA_COMPANY "\x01"'
# const 'MBEDTLS_OID_PKCS1' has unsupported value 'MBEDTLS_OID_PKCS "\x01"'
# const 'MBEDTLS_OID_PKCS5' has unsupported value 'MBEDTLS_OID_PKCS "\x05"'
# const 'MBEDTLS_OID_PKCS7' has unsupported value 'MBEDTLS_OID_PKCS "\x07"'
# const 'MBEDTLS_OID_PKCS9' has unsupported value 'MBEDTLS_OID_PKCS "\x09"'
# const 'MBEDTLS_OID_PKCS12' has unsupported value 'MBEDTLS_OID_PKCS "\x0c"'
# const 'MBEDTLS_OID_PKCS1_RSA' has unsupported value 'MBEDTLS_OID_PKCS1 "\x01"'
# const 'MBEDTLS_OID_PKCS1_MD5' has unsupported value 'MBEDTLS_OID_PKCS1 "\x04"'
# const 'MBEDTLS_OID_PKCS1_SHA1' has unsupported value 'MBEDTLS_OID_PKCS1 "\x05"'
# const 'MBEDTLS_OID_PKCS1_SHA224' has unsupported value 'MBEDTLS_OID_PKCS1 "\x0e"'
# const 'MBEDTLS_OID_PKCS1_SHA256' has unsupported value 'MBEDTLS_OID_PKCS1 "\x0b"'
# const 'MBEDTLS_OID_PKCS1_SHA384' has unsupported value 'MBEDTLS_OID_PKCS1 "\x0c"'
# const 'MBEDTLS_OID_PKCS1_SHA512' has unsupported value 'MBEDTLS_OID_PKCS1 "\x0d"'
# const 'MBEDTLS_OID_PKCS9_EMAIL' has unsupported value 'MBEDTLS_OID_PKCS9 "\x01"'
# const 'MBEDTLS_OID_RSASSA_PSS' has unsupported value 'MBEDTLS_OID_PKCS1 "\x0a"'
# const 'MBEDTLS_OID_MGF1' has unsupported value 'MBEDTLS_OID_PKCS1 "\x08"'
# const 'MBEDTLS_OID_DIGEST_ALG_MD5' has unsupported value 'MBEDTLS_OID_RSA_COMPANY "\x02\x05"'
# const 'MBEDTLS_OID_DIGEST_ALG_SHA1' has unsupported value 'MBEDTLS_OID_ISO_IDENTIFIED_ORG MBEDTLS_OID_OIW_SECSIG_SHA1'
# const 'MBEDTLS_OID_DIGEST_ALG_SHA224' has unsupported value 'MBEDTLS_OID_NIST_ALG "\x02\x04"'
# const 'MBEDTLS_OID_DIGEST_ALG_SHA256' has unsupported value 'MBEDTLS_OID_NIST_ALG "\x02\x01"'
# const 'MBEDTLS_OID_DIGEST_ALG_SHA384' has unsupported value 'MBEDTLS_OID_NIST_ALG "\x02\x02"'
# const 'MBEDTLS_OID_DIGEST_ALG_SHA512' has unsupported value 'MBEDTLS_OID_NIST_ALG "\x02\x03"'
# const 'MBEDTLS_OID_DIGEST_ALG_RIPEMD160' has unsupported value 'MBEDTLS_OID_TELETRUST "\x03\x02\x01"'
# const 'MBEDTLS_OID_HMAC_SHA1' has unsupported value 'MBEDTLS_OID_RSA_COMPANY "\x02\x07"'
# const 'MBEDTLS_OID_HMAC_SHA224' has unsupported value 'MBEDTLS_OID_RSA_COMPANY "\x02\x08"'
# const 'MBEDTLS_OID_HMAC_SHA256' has unsupported value 'MBEDTLS_OID_RSA_COMPANY "\x02\x09"'
# const 'MBEDTLS_OID_HMAC_SHA384' has unsupported value 'MBEDTLS_OID_RSA_COMPANY "\x02\x0A"'
# const 'MBEDTLS_OID_HMAC_SHA512' has unsupported value 'MBEDTLS_OID_RSA_COMPANY "\x02\x0B"'
# const 'MBEDTLS_OID_DES_CBC' has unsupported value 'MBEDTLS_OID_ISO_IDENTIFIED_ORG MBEDTLS_OID_OIW_SECSIG_ALG "\x07"'
# const 'MBEDTLS_OID_DES_EDE3_CBC' has unsupported value 'MBEDTLS_OID_RSA_COMPANY "\x03\x07"'
# const 'MBEDTLS_OID_AES' has unsupported value 'MBEDTLS_OID_NIST_ALG "\x01"'
# const 'MBEDTLS_OID_AES128_KW' has unsupported value 'MBEDTLS_OID_AES "\x05"'
# const 'MBEDTLS_OID_AES128_KWP' has unsupported value 'MBEDTLS_OID_AES "\x08"'
# const 'MBEDTLS_OID_AES192_KW' has unsupported value 'MBEDTLS_OID_AES "\x19"'
# const 'MBEDTLS_OID_AES192_KWP' has unsupported value 'MBEDTLS_OID_AES "\x1c"'
# const 'MBEDTLS_OID_AES256_KW' has unsupported value 'MBEDTLS_OID_AES "\x2d"'
# const 'MBEDTLS_OID_AES256_KWP' has unsupported value 'MBEDTLS_OID_AES "\x30"'
# const 'MBEDTLS_OID_PKCS5_PBKDF2' has unsupported value 'MBEDTLS_OID_PKCS5 "\x0c"'
# const 'MBEDTLS_OID_PKCS5_PBES2' has unsupported value 'MBEDTLS_OID_PKCS5 "\x0d"'
# const 'MBEDTLS_OID_PKCS5_PBMAC1' has unsupported value 'MBEDTLS_OID_PKCS5 "\x0e"'
# const 'MBEDTLS_OID_PKCS5_PBE_MD5_DES_CBC' has unsupported value 'MBEDTLS_OID_PKCS5 "\x03"'
# const 'MBEDTLS_OID_PKCS5_PBE_MD5_RC2_CBC' has unsupported value 'MBEDTLS_OID_PKCS5 "\x06"'
# const 'MBEDTLS_OID_PKCS5_PBE_SHA1_DES_CBC' has unsupported value 'MBEDTLS_OID_PKCS5 "\x0a"'
# const 'MBEDTLS_OID_PKCS5_PBE_SHA1_RC2_CBC' has unsupported value 'MBEDTLS_OID_PKCS5 "\x0b"'
# const 'MBEDTLS_OID_PKCS7_DATA' has unsupported value 'MBEDTLS_OID_PKCS7 "\x01"'
# const 'MBEDTLS_OID_PKCS7_SIGNED_DATA' has unsupported value 'MBEDTLS_OID_PKCS7 "\x02"'
# const 'MBEDTLS_OID_PKCS7_ENVELOPED_DATA' has unsupported value 'MBEDTLS_OID_PKCS7 "\x03"'
# const 'MBEDTLS_OID_PKCS7_SIGNED_AND_ENVELOPED_DATA' has unsupported value 'MBEDTLS_OID_PKCS7 "\x04"'
# const 'MBEDTLS_OID_PKCS7_DIGESTED_DATA' has unsupported value 'MBEDTLS_OID_PKCS7 "\x05"'
# const 'MBEDTLS_OID_PKCS7_ENCRYPTED_DATA' has unsupported value 'MBEDTLS_OID_PKCS7 "\x06"'
# const 'MBEDTLS_OID_PKCS9_CSR_EXT_REQ' has unsupported value 'MBEDTLS_OID_PKCS9 "\x0e"'
# const 'MBEDTLS_OID_PKCS12_PBE' has unsupported value 'MBEDTLS_OID_PKCS12 "\x01"'
# const 'MBEDTLS_OID_PKCS12_PBE_SHA1_DES3_EDE_CBC' has unsupported value 'MBEDTLS_OID_PKCS12_PBE "\x03"'
# const 'MBEDTLS_OID_PKCS12_PBE_SHA1_DES2_EDE_CBC' has unsupported value 'MBEDTLS_OID_PKCS12_PBE "\x04"'
# const 'MBEDTLS_OID_PKCS12_PBE_SHA1_RC2_128_CBC' has unsupported value 'MBEDTLS_OID_PKCS12_PBE "\x05"'
# const 'MBEDTLS_OID_PKCS12_PBE_SHA1_RC2_40_CBC' has unsupported value 'MBEDTLS_OID_PKCS12_PBE "\x06"'
# const 'MBEDTLS_OID_EC_ALG_UNRESTRICTED' has unsupported value 'MBEDTLS_OID_ANSI_X9_62 "\x02\01"'
# const 'MBEDTLS_OID_EC_ALG_ECDH' has unsupported value 'MBEDTLS_OID_CERTICOM "\x01\x0c"'
# const 'MBEDTLS_OID_EC_GRP_SECP192R1' has unsupported value 'MBEDTLS_OID_ANSI_X9_62 "\x03\x01\x01"'
# const 'MBEDTLS_OID_EC_GRP_SECP224R1' has unsupported value 'MBEDTLS_OID_CERTICOM "\x00\x21"'
# const 'MBEDTLS_OID_EC_GRP_SECP256R1' has unsupported value 'MBEDTLS_OID_ANSI_X9_62 "\x03\x01\x07"'
# const 'MBEDTLS_OID_EC_GRP_SECP384R1' has unsupported value 'MBEDTLS_OID_CERTICOM "\x00\x22"'
# const 'MBEDTLS_OID_EC_GRP_SECP521R1' has unsupported value 'MBEDTLS_OID_CERTICOM "\x00\x23"'
# const 'MBEDTLS_OID_EC_GRP_SECP192K1' has unsupported value 'MBEDTLS_OID_CERTICOM "\x00\x1f"'
# const 'MBEDTLS_OID_EC_GRP_SECP224K1' has unsupported value 'MBEDTLS_OID_CERTICOM "\x00\x20"'
# const 'MBEDTLS_OID_EC_GRP_SECP256K1' has unsupported value 'MBEDTLS_OID_CERTICOM "\x00\x0a"'
# const 'MBEDTLS_OID_EC_BRAINPOOL_V1' has unsupported value 'MBEDTLS_OID_TELETRUST "\x03\x03\x02\x08\x01\x01"'
# const 'MBEDTLS_OID_EC_GRP_BP256R1' has unsupported value 'MBEDTLS_OID_EC_BRAINPOOL_V1 "\x07"'
# const 'MBEDTLS_OID_EC_GRP_BP384R1' has unsupported value 'MBEDTLS_OID_EC_BRAINPOOL_V1 "\x0B"'
# const 'MBEDTLS_OID_EC_GRP_BP512R1' has unsupported value 'MBEDTLS_OID_EC_BRAINPOOL_V1 "\x0D"'
# const 'MBEDTLS_OID_ANSI_X9_62_FIELD_TYPE' has unsupported value 'MBEDTLS_OID_ANSI_X9_62 "\x01"'
# const 'MBEDTLS_OID_ANSI_X9_62_PRIME_FIELD' has unsupported value 'MBEDTLS_OID_ANSI_X9_62_FIELD_TYPE "\x01"'
# const 'MBEDTLS_OID_ANSI_X9_62_SIG' has unsupported value 'MBEDTLS_OID_ANSI_X9_62 "\x04"'
# const 'MBEDTLS_OID_ANSI_X9_62_SIG_SHA2' has unsupported value 'MBEDTLS_OID_ANSI_X9_62_SIG "\x03"'
# const 'MBEDTLS_OID_ECDSA_SHA1' has unsupported value 'MBEDTLS_OID_ANSI_X9_62_SIG "\x01"'
# const 'MBEDTLS_OID_ECDSA_SHA224' has unsupported value 'MBEDTLS_OID_ANSI_X9_62_SIG_SHA2 "\x01"'
# const 'MBEDTLS_OID_ECDSA_SHA256' has unsupported value 'MBEDTLS_OID_ANSI_X9_62_SIG_SHA2 "\x02"'
# const 'MBEDTLS_OID_ECDSA_SHA384' has unsupported value 'MBEDTLS_OID_ANSI_X9_62_SIG_SHA2 "\x03"'
# const 'MBEDTLS_OID_ECDSA_SHA512' has unsupported value 'MBEDTLS_OID_ANSI_X9_62_SIG_SHA2 "\x04"'

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}

const
  MBEDTLS_ERR_OID_NOT_FOUND* = -0x0000002E
  MBEDTLS_ERR_OID_BUF_TOO_SMALL* = -0x0000000B
  MBEDTLS_OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER* = (1 shl typeof(1)(0))
  MBEDTLS_OID_X509_EXT_SUBJECT_KEY_IDENTIFIER* = (1 shl typeof(1)(1))
  MBEDTLS_OID_X509_EXT_KEY_USAGE* = (1 shl typeof(1)(2))
  MBEDTLS_OID_X509_EXT_CERTIFICATE_POLICIES* = (1 shl typeof(1)(3))
  MBEDTLS_OID_X509_EXT_POLICY_MAPPINGS* = (1 shl typeof(1)(4))
  MBEDTLS_OID_X509_EXT_SUBJECT_ALT_NAME* = (1 shl typeof(1)(5))
  MBEDTLS_OID_X509_EXT_ISSUER_ALT_NAME* = (1 shl typeof(1)(6))
  MBEDTLS_OID_X509_EXT_SUBJECT_DIRECTORY_ATTRS* = (1 shl typeof(1)(7))
  MBEDTLS_OID_X509_EXT_BASIC_CONSTRAINTS* = (1 shl typeof(1)(8))
  MBEDTLS_OID_X509_EXT_NAME_CONSTRAINTS* = (1 shl typeof(1)(9))
  MBEDTLS_OID_X509_EXT_POLICY_CONSTRAINTS* = (1 shl typeof(1)(10))
  MBEDTLS_OID_X509_EXT_EXTENDED_KEY_USAGE* = (1 shl typeof(1)(11))
  MBEDTLS_OID_X509_EXT_CRL_DISTRIBUTION_POINTS* = (1 shl typeof(1)(12))
  MBEDTLS_OID_X509_EXT_INIHIBIT_ANYPOLICY* = (1 shl typeof(1)(13))
  MBEDTLS_OID_X509_EXT_FRESHEST_CRL* = (1 shl typeof(1)(14))
  MBEDTLS_OID_X509_EXT_NS_CERT_TYPE* = (1 shl typeof(1)(16))
  MBEDTLS_OID_ISO_MEMBER_BODIES* = "*"
  MBEDTLS_OID_ISO_IDENTIFIED_ORG* = "+"
  MBEDTLS_OID_ISO_CCITT_DS* = "U"
  MBEDTLS_OID_ISO_ITU_COUNTRY* = "`"
  MBEDTLS_OID_COUNTRY_US* = "ÜH"
  MBEDTLS_OID_ORG_RSA_DATA_SECURITY* = "Ü˜\r"
  MBEDTLS_OID_ORG_ANSI_X9_62* = "Œ="
  MBEDTLS_OID_ORG_DOD* = "\x06"
  MBEDTLS_OID_ORG_OIW* = "\x0E"
  MBEDTLS_OID_ORG_CERTICOM* = "Å\x04"
  MBEDTLS_OID_ORG_TELETRUST* = "$"
  MBEDTLS_OID_ORGANIZATION* = "\x01"
  MBEDTLS_OID_ORG_GOV* = "e"
  MBEDTLS_OID_ORG_NETSCAPE* = "Ü¯B"
  MBEDTLS_OID_UID* = "\tí&âìÚ,d\x01\x01"
  MBEDTLS_OID_DOMAIN_COMPONENT* = "\tí&âìÚ,d\x01\x19"
  MBEDTLS_OID_RSA_SHA_OBS* = "+\x0E\x03\x02\x1D"
type
  mbedtls_oid_descriptor_t* {.bycopy.} = object
    private_asn1*: cstring
    private_asn1_len*: uint
    private_name*: cstring
    private_description*: cstring

proc mbedtls_oid_get_numeric_string*(buf: cstring; size: uint;
                                     oid: ptr mbedtls_asn1_buf): cint {.importc,
    cdecl.}
proc mbedtls_oid_get_x509_ext_type*(oid: ptr mbedtls_asn1_buf;
                                    ext_type: ptr cint): cint {.importc, cdecl.}
proc mbedtls_oid_get_attr_short_name*(oid: ptr mbedtls_asn1_buf;
                                      short_name: ptr cstring): cint {.importc,
    cdecl.}
proc mbedtls_oid_get_pk_alg*(oid: ptr mbedtls_asn1_buf;
                             pk_alg: ptr mbedtls_pk_type_t): cint {.importc,
    cdecl.}
proc mbedtls_oid_get_oid_by_pk_alg*(pk_alg: mbedtls_pk_type_t; oid: ptr cstring;
                                    olen: ptr uint): cint {.importc, cdecl.}
proc mbedtls_oid_get_ec_grp*(oid: ptr mbedtls_asn1_buf;
                             grp_id: ptr mbedtls_ecp_group_id): cint {.importc,
    cdecl.}
proc mbedtls_oid_get_oid_by_ec_grp*(grp_id: mbedtls_ecp_group_id;
                                    oid: ptr cstring; olen: ptr uint): cint {.
    importc, cdecl.}
proc mbedtls_oid_get_sig_alg*(oid: ptr mbedtls_asn1_buf;
                              md_alg: ptr mbedtls_md_type_t;
                              pk_alg: ptr mbedtls_pk_type_t): cint {.importc,
    cdecl.}
proc mbedtls_oid_get_sig_alg_desc*(oid: ptr mbedtls_asn1_buf; desc: ptr cstring): cint {.
    importc, cdecl.}
proc mbedtls_oid_get_oid_by_sig_alg*(pk_alg: mbedtls_pk_type_t;
                                     md_alg: mbedtls_md_type_t;
                                     oid: ptr cstring; olen: ptr uint): cint {.
    importc, cdecl.}
proc mbedtls_oid_get_md_hmac*(oid: ptr mbedtls_asn1_buf;
                              md_hmac: ptr mbedtls_md_type_t): cint {.importc,
    cdecl.}
proc mbedtls_oid_get_md_alg*(oid: ptr mbedtls_asn1_buf;
                             md_alg: ptr mbedtls_md_type_t): cint {.importc,
    cdecl.}
proc mbedtls_oid_get_extended_key_usage*(oid: ptr mbedtls_asn1_buf;
    desc: ptr cstring): cint {.importc, cdecl.}
proc mbedtls_oid_get_certificate_policies*(oid: ptr mbedtls_asn1_buf;
    desc: ptr cstring): cint {.importc, cdecl.}
proc mbedtls_oid_get_oid_by_md*(md_alg: mbedtls_md_type_t; oid: ptr cstring;
                                olen: ptr uint): cint {.importc, cdecl.}
proc mbedtls_oid_get_cipher_alg*(oid: ptr mbedtls_asn1_buf;
                                 cipher_alg: ptr mbedtls_cipher_type_t): cint {.
    importc, cdecl.}
proc mbedtls_oid_get_pkcs12_pbe_alg*(oid: ptr mbedtls_asn1_buf;
                                     md_alg: ptr mbedtls_md_type_t;
                                     cipher_alg: ptr mbedtls_cipher_type_t): cint {.
    importc, cdecl.}
{.pop.}
