# TODO: Put the .compile. pragma in one of the file using it without breaking everything
{.compile: "./mbedtls/csources/library/hash_info.c".}
{.passc: "-I./mbedtls/csources/include".}
{.passc: "-I./mbedtls/csources/library".}
