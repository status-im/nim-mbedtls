{.compile: "./mbedtls/csources/library/memory_buffer_alloc.c".}

{.push hint[ConvFromXtoItselfNotNeeded]: off.}

{.experimental: "codeReordering".}
{.passc: "-I./mbedtls/csources/include".}
{.passc: "-I./mbedtls/csources/library".}

const
  MBEDTLS_MEMORY_ALIGN_MULTIPLE* = 4
  MBEDTLS_MEMORY_VERIFY_NONE* = 0
  MBEDTLS_MEMORY_VERIFY_ALLOC* = (1 shl typeof(1)(0))
  MBEDTLS_MEMORY_VERIFY_FREE* = (1 shl typeof(1)(1))
  MBEDTLS_MEMORY_VERIFY_ALWAYS* = (MBEDTLS_MEMORY_VERIFY_ALLOC or
      typeof(MBEDTLS_MEMORY_VERIFY_ALLOC)(MBEDTLS_MEMORY_VERIFY_FREE))
proc mbedtls_memory_buffer_alloc_init*(buf: ptr byte; len: uint) {.importc,
    cdecl.}
proc mbedtls_memory_buffer_alloc_free*() {.importc, cdecl.}
proc mbedtls_memory_buffer_set_verify*(verify: cint) {.importc, cdecl.}
proc mbedtls_memory_buffer_alloc_verify*(): cint {.importc, cdecl.}
proc mbedtls_memory_buffer_alloc_self_test*(verbose: cint): cint {.importc,
    cdecl.}
{.pop.}
