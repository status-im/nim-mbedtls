{.used.}
{.used.}

import os, strutils

const
  mbedtlsPath* = currentSourcePath.rsplit({DirSep, AltSep}, 1)[0] & "/" &
                "csources" & "/"
  mbedtlsIncPath* = mbedtlsPath & "include/"
  mbedtlsLibPath* = mbedtlsPath & "library/"

{.passc: "-I" & quoteShell(mbedtlsIncPath).}
{.passc: "-I" & quoteShell(mbedtlsLibPath).}
