/* zcio/archive.h - read/write archive entries (tar, gz, ...) via libarchive.
 *
 * Port of archive_stream. Optional: compiled only when ZCIO_WITH_ARCHIVE is on.
 * When absent, the creators return NULL and set ZCIO_ERR_UNSUPPORTED.
 */
#ifndef ZCIO_ARCHIVE_H
#define ZCIO_ARCHIVE_H

#include "zcio/types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct zcio_archive zcio_archive;

typedef enum zcio_archive_mode : int32_t {
    ZCIO_ARCHIVE_READ  = 0,
    ZCIO_ARCHIVE_WRITE = 1,
} zcio_archive_mode;

/* True if the archive backend was compiled in. */
ZCIO_API bool zcio_archive_available(void);

ZCIO_API ZCIO_NODISCARD zcio_archive *zcio_archive_open(const char *path, zcio_archive_mode mode);
ZCIO_API void zcio_archive_close(zcio_archive *a);

/* List entry names. Returns malloc'd array of malloc'd strings; free with
 * zcio_strv_free (declared in dns.h) using *out_count. */
ZCIO_API char **zcio_archive_entries(zcio_archive *a, size_t *out_count);

/* Select the active entry by name (read mode) or create it (write mode). */
ZCIO_API int   zcio_archive_set_entry(zcio_archive *a, const char *name);
/* Read the whole active entry into a malloc'd NUL-terminated buffer (read mode). */
ZCIO_API char *zcio_archive_entry_string(zcio_archive *a);

ZCIO_API int64_t zcio_archive_write(zcio_archive *a, const void *data, size_t n);
ZCIO_API int64_t zcio_archive_read (zcio_archive *a, void *buf, size_t n);

#ifdef __cplusplus
}
#endif

#endif /* ZCIO_ARCHIVE_H */
