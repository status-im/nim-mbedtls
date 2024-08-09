# Mbed-TLS

![Stability: experimental](https://img.shields.io/badge/stability-experimental-orange.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![License: Apache](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

An [Mbed-TLS](https://github.com/Mbed-TLS/mbedtls/) wrapper for Nim, fully integrated with the Nim build system.

Applications using `nim-mbedtls` are fully stand-alone, needing no additional DLL or shared library.

## Usage

For now, the library is just a wrapper which exposes the raw C functions of mbedtls.

For each `mbedtls` header file, a corresponding Nim file exists - `ssl.h` ~ `mbedtls/ssl.nim`.

```nim
# You can import the whole library
import mbedtls

# ... or simply parts thereof, which can save compilation time
import mbedtls/ssl
```

## Installation

You can install the development version of the library through nimble with the following command:

```
nimble install https://github.com/status-im/nim-mbedtls.git
```

`Mbed-TLS` itself is compiled as part of your project - there is no need to install any third-party libraries.

## License

Licensed and distributed under either of

* MIT license: [LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT

or

* Apache License, Version 2.0, ([LICENSE-APACHEv2](LICENSE-APACHEv2) or http://www.apache.org/licenses/LICENSE-2.0)

at your option. This file may not be copied, modified, or distributed except according to those terms.
