# Copyright (c) 2023-2023 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0,
#  * MIT license
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

packageName   = "mbedtls"
version       = "0.0.1"
author        = "Status Research & Development GmbH"
description   = "Mbed-TLS wrapper in Nim"
license       = "MIT or Apache License 2.0"

before install:
  exec "git submodule update --init"
  exec "make --silent -C mbedtls/csources/library error.c"
  exec "make --silent -C mbedtls/csources/library version_features.c"
  exec "make --silent -C mbedtls/csources/library ssl_debug_helpers_generated.c"
  # exec "make --silent -C mbedtls/csources/library psa_crypto_driver_wrappers.c"
  # Unnecessary. Requires python `jsonschema` module
