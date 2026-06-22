/* zcio/types.h - shared result codes, attributes, and primitive typedefs. */
#ifndef ZCIO_TYPES_H
#define ZCIO_TYPES_H

#include <stddef.h>
#include <stdint.h>

/* `bool` is a keyword in C++ and in C23; <stdbool.h> provides it on older C.
 * Never include the deprecated/removed <cstdbool> for C++. */
#if !defined(__cplusplus)
#  include <stdbool.h>
#endif

/* Enum with a fixed underlying type: standard in C++11 and C23, but not C11.
 * The fixed width pins these enums to a stable ABI size; on pre-C23 C we fall
 * back to a plain enum (all enumerators fit in int, so the size matches). */
#if defined(__cplusplus) || (defined(__STDC_VERSION__) && __STDC_VERSION__ >= 202311L)
#  define ZCIO_ENUM(NAME, TYPE) enum NAME : TYPE
#else
#  define ZCIO_ENUM(NAME, TYPE) enum NAME
#endif

/* --- export / linkage --------------------------------------------------- *
 * For a shared build, consumers must see ZCIO_SHARED to get dllimport on
 * Windows. The install/export interface defines ZCIO_SHARED; ZCIO_BUILDING is
 * set only while compiling the library itself (-> dllexport). */
#if defined(_WIN32) && (defined(ZCIO_SHARED) || defined(ZCIO_BUILD_SHARED))
#  if defined(ZCIO_BUILDING)
#    define ZCIO_API __declspec(dllexport)
#  else
#    define ZCIO_API __declspec(dllimport)
#  endif
#else
#  define ZCIO_API
#endif

/* C23 gives us [[nodiscard]] / [[maybe_unused]] as standard attributes. Guard
 * for older toolchains and C++ so the public header stays universally includable.
 *
 * On GCC/Clang prefer the __attribute__ spelling: ZCIO_API places this macro
 * after __declspec(dllexport/dllimport) on Windows shared builds, and a C23
 * [[nodiscard]] in that position binds to the return *type* (clang-cl rejects it
 * with "attribute cannot be applied to types"). The GNU attribute attaches to
 * the function regardless of where it sits relative to __declspec. */
#if defined(__GNUC__) || defined(__clang__)
#  define ZCIO_NODISCARD     __attribute__((warn_unused_result))
#  define ZCIO_MAYBE_UNUSED  __attribute__((unused))
#elif defined(__has_c_attribute)
#  if __has_c_attribute(nodiscard)
#    define ZCIO_NODISCARD [[nodiscard]]
#  endif
#  if __has_c_attribute(maybe_unused)
#    define ZCIO_MAYBE_UNUSED [[maybe_unused]]
#  endif
#endif
#ifndef ZCIO_NODISCARD
#  define ZCIO_NODISCARD
#endif
#ifndef ZCIO_MAYBE_UNUSED
#  define ZCIO_MAYBE_UNUSED
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* --- result codes ------------------------------------------------------- *
 * Mirrors (and extends) the original iostreams io_result_t so existing C
 * consumers port cleanly. Negative == error, 0 == success. */
typedef ZCIO_ENUM(zcio_result, int32_t) {
    ZCIO_OK                 =  0,
    ZCIO_ERR                = -1,  /* generic / unspecified failure          */
    ZCIO_ERR_INVALID_ARG    = -2,  /* a NULL or out-of-range argument        */
    ZCIO_ERR_CONNECT        = -3,  /* connection establishment failed        */
    ZCIO_ERR_TIMEOUT        = -4,  /* operation timed out                    */
    ZCIO_ERR_EOF            = -5,  /* peer closed / end of stream            */
    ZCIO_ERR_TLS            = -6,  /* TLS handshake or I/O failure           */
    ZCIO_ERR_ARCHIVE        = -7,  /* archive backend failure                */
    ZCIO_ERR_NOMEM          = -8,  /* allocation failed                      */
    ZCIO_ERR_UNSUPPORTED    = -9,  /* feature compiled out / not available   */
    ZCIO_ERR_WOULDBLOCK     = -10, /* non-blocking op has no data right now  */
    ZCIO_ERR_DNS            = -11, /* name resolution failed                 */
    ZCIO_ERR_PROTOCOL       = -12, /* malformed protocol data (e.g. HTTP)    */
} zcio_result;

/* seek "which" mask -- read side, write side, or both. */
typedef ZCIO_ENUM(zcio_seek_which, uint32_t) {
    ZCIO_SEEK_READ  = 1u << 0,
    ZCIO_SEEK_WRITE = 1u << 1,
    ZCIO_SEEK_BOTH  = ZCIO_SEEK_READ | ZCIO_SEEK_WRITE,
} zcio_seek_which;

/* seek origin -- matches stdio SEEK_SET/CUR/END ordering. */
typedef ZCIO_ENUM(zcio_seek_origin, int32_t) {
    ZCIO_SEEK_SET = 0,
    ZCIO_SEEK_CUR = 1,
    ZCIO_SEEK_END = 2,
} zcio_seek_origin;

/* Human-readable string for a result code (static storage, never freed). */
ZCIO_API const char *zcio_result_str(zcio_result r);

/* Thread-local last-error string, set by the most recent failing call on the
 * current thread. Returns "" when no error has been recorded. Lets FFI layers
 * surface a message without threading error buffers through every signature. */
ZCIO_API const char *zcio_last_error(void);

#ifdef __cplusplus
}
#endif

#endif /* ZCIO_TYPES_H */
