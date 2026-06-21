/* src/archive.c - read/write archive entries via libarchive.
 *
 * Port of archive_stream.cpp. The real implementation is compiled only when
 * ZCIO_WITH_ARCHIVE is defined (and libarchive is available). Otherwise every
 * entry point degrades gracefully: zcio_archive_available() returns false, the
 * creators return NULL and set ZCIO_ERR_UNSUPPORTED, and read/write return
 * ZCIO_ERR_UNSUPPORTED.
 *
 * Memory ownership:
 *   - zcio_archive_entries returns a malloc'd array of malloc'd strings; the
 *     caller frees it with zcio_strv_free(v, count) (declared in dns.h).
 *   - zcio_archive_entry_string returns a malloc'd NUL-terminated buffer that
 *     the caller frees with free().
 */
#include "zcio/archive.h"
#include "zcio/dns.h"   /* zcio_strv_free */
#include "internal.h"

bool zcio_archive_available(void) {
#ifdef ZCIO_WITH_ARCHIVE
    return true;
#else
    return false;
#endif
}

#ifdef ZCIO_WITH_ARCHIVE

#include <archive.h>
#include <archive_entry.h>

struct zcio_archive {
    zcio_archive_mode    mode;
    char                *path;
    struct archive      *write_arc;   /* open write handle (write mode)        */
    struct archive_entry *entry;      /* active write entry (write mode)       */
    /* read-mode active entry contents (read whole entry into memory)          */
    char                *rbuf;        /* malloc'd entry bytes                   */
    size_t               rlen;        /* size of rbuf                           */
    size_t               rpos;        /* read cursor into rbuf                  */
    /* write-mode pending entry contents                                       */
    char                *wbuf;
    size_t               wlen;
    size_t               wcap;
};

/* ----------------------------- write helpers ---------------------------- */

static void flush_write_entry(zcio_archive *a) {
    if (!a->write_arc || !a->entry) return;
    archive_entry_set_size(a->entry, (int64_t)a->wlen);
    archive_entry_set_filetype(a->entry, AE_IFREG);
    archive_entry_set_perm(a->entry, 0644);
    archive_write_header(a->write_arc, a->entry);
    if (a->wlen)
        archive_write_data(a->write_arc, a->wbuf, a->wlen);
    archive_entry_free(a->entry);
    a->entry = NULL;
    free(a->wbuf);
    a->wbuf = NULL;
    a->wlen = a->wcap = 0;
}

/* ------------------------------ open/close ------------------------------ */

zcio_archive *zcio_archive_open(const char *path, zcio_archive_mode mode) {
    if (!path) { zcio_fail_(ZCIO_ERR_INVALID_ARG, "archive: NULL path"); return NULL; }

    zcio_archive *a = (zcio_archive *)zcio_xcalloc(1, sizeof *a);
    if (!a) { zcio_fail_(ZCIO_ERR_NOMEM, "archive: out of memory"); return NULL; }
    a->mode = mode;
    a->path = zcio_strdup_(path);
    if (!a->path) { free(a); zcio_fail_(ZCIO_ERR_NOMEM, "archive: out of memory"); return NULL; }

    if (mode == ZCIO_ARCHIVE_WRITE) {
        a->write_arc = archive_write_new();
        if (!a->write_arc) {
            free(a->path); free(a);
            zcio_fail_(ZCIO_ERR_ARCHIVE, "archive: archive_write_new failed");
            return NULL;
        }
        archive_write_set_format_pax_restricted(a->write_arc);
        archive_write_add_filter_gzip(a->write_arc);
        if (archive_write_open_filename(a->write_arc, path) != ARCHIVE_OK) {
            zcio_fail_(ZCIO_ERR_ARCHIVE, "archive: open '%s' for write failed: %s",
                       path, archive_error_string(a->write_arc));
            archive_write_free(a->write_arc);
            free(a->path); free(a);
            return NULL;
        }
    }
    /* read mode opens lazily per operation (mirrors the C++ port). */
    return a;
}

void zcio_archive_close(zcio_archive *a) {
    if (!a) return;
    if (a->mode == ZCIO_ARCHIVE_WRITE && a->write_arc) {
        if (a->entry) flush_write_entry(a);
        archive_write_close(a->write_arc);
        archive_write_free(a->write_arc);
    }
    if (a->entry) archive_entry_free(a->entry);
    free(a->rbuf);
    free(a->wbuf);
    free(a->path);
    free(a);
}

/* ---------------------------- list entries ------------------------------ */

char **zcio_archive_entries(zcio_archive *a, size_t *out_count) {
    if (out_count) *out_count = 0;
    if (!a) { zcio_fail_(ZCIO_ERR_INVALID_ARG, "archive: NULL handle"); return NULL; }
    if (a->mode != ZCIO_ARCHIVE_READ) {
        zcio_fail_(ZCIO_ERR_UNSUPPORTED, "archive: entries() only in read mode");
        return NULL;
    }

    struct archive *arc = archive_read_new();
    if (!arc) { zcio_fail_(ZCIO_ERR_ARCHIVE, "archive: archive_read_new failed"); return NULL; }
    archive_read_support_format_all(arc);
    archive_read_support_filter_all(arc);

    if (archive_read_open_filename(arc, a->path, 10240) != ARCHIVE_OK) {
        zcio_fail_(ZCIO_ERR_ARCHIVE, "archive: open '%s' failed: %s",
                   a->path, archive_error_string(arc));
        archive_read_free(arc);
        return NULL;
    }

    char **list = NULL;
    size_t count = 0, cap = 0;
    struct archive_entry *e;
    while (archive_read_next_header(arc, &e) == ARCHIVE_OK) {
        const char *name = archive_entry_pathname(e);
        char *dup = zcio_strdup_(name ? name : "");
        if (!dup) goto oom;
        if (count == cap) {
            size_t ncap = cap ? cap * 2 : 8;
            char **nl = (char **)realloc(list, ncap * sizeof *nl);
            if (!nl) { free(dup); goto oom; }
            list = nl; cap = ncap;
        }
        list[count++] = dup;
        archive_read_data_skip(arc);
    }

    archive_read_close(arc);
    archive_read_free(arc);
    if (out_count) *out_count = count;
    return list;

oom:
    archive_read_close(arc);
    archive_read_free(arc);
    zcio_strv_free(list, count);
    zcio_fail_(ZCIO_ERR_NOMEM, "archive: out of memory listing entries");
    return NULL;
}

/* ----------------------------- set_entry -------------------------------- */

int zcio_archive_set_entry(zcio_archive *a, const char *name) {
    if (!a || !name) return zcio_fail_(ZCIO_ERR_INVALID_ARG, "archive: NULL arg");

    if (a->mode == ZCIO_ARCHIVE_WRITE) {
        /* flush the previous entry, then start a new one. */
        if (a->entry) flush_write_entry(a);
        a->entry = archive_entry_new();
        if (!a->entry) return zcio_fail_(ZCIO_ERR_ARCHIVE, "archive: archive_entry_new failed");
        archive_entry_set_pathname(a->entry, name);
        free(a->wbuf); a->wbuf = NULL; a->wlen = a->wcap = 0;
        return ZCIO_OK;
    }

    /* read mode: locate the entry and load it fully into a->rbuf. */
    free(a->rbuf); a->rbuf = NULL; a->rlen = a->rpos = 0;

    struct archive *arc = archive_read_new();
    if (!arc) return zcio_fail_(ZCIO_ERR_ARCHIVE, "archive: archive_read_new failed");
    archive_read_support_format_all(arc);
    archive_read_support_filter_all(arc);

    if (archive_read_open_filename(arc, a->path, 10240) != ARCHIVE_OK) {
        int rc = zcio_fail_(ZCIO_ERR_ARCHIVE, "archive: open '%s' failed: %s",
                            a->path, archive_error_string(arc));
        archive_read_free(arc);
        return rc;
    }

    struct archive_entry *e;
    while (archive_read_next_header(arc, &e) == ARCHIVE_OK) {
        const char *pname = archive_entry_pathname(e);
        if (pname && strcmp(pname, name) == 0) {
            int64_t size = archive_entry_size(e);
            if (size < 0) size = 0;
            char *buf = (char *)zcio_xmalloc((size_t)size + 1);
            if (!buf) {
                archive_read_close(arc); archive_read_free(arc);
                return zcio_fail_(ZCIO_ERR_NOMEM, "archive: out of memory");
            }
            size_t got = 0;
            while (got < (size_t)size) {
                la_ssize_t r = archive_read_data(arc, buf + got, (size_t)size - got);
                if (r <= 0) break;
                got += (size_t)r;
            }
            buf[got] = '\0';
            a->rbuf = buf;
            a->rlen = got;
            a->rpos = 0;
            archive_read_close(arc);
            archive_read_free(arc);
            return ZCIO_OK;
        }
        archive_read_data_skip(arc);
    }

    archive_read_close(arc);
    archive_read_free(arc);
    return zcio_fail_(ZCIO_ERR_ARCHIVE, "archive: entry not found: %s", name);
}

/* --------------------------- entry_string ------------------------------- */

char *zcio_archive_entry_string(zcio_archive *a) {
    if (!a) { zcio_fail_(ZCIO_ERR_INVALID_ARG, "archive: NULL handle"); return NULL; }
    if (a->mode != ZCIO_ARCHIVE_READ) {
        zcio_fail_(ZCIO_ERR_UNSUPPORTED, "archive: entry_string only in read mode");
        return NULL;
    }
    if (!a->rbuf) { zcio_fail_(ZCIO_ERR_ARCHIVE, "archive: no active entry"); return NULL; }

    char *out = (char *)zcio_xmalloc(a->rlen + 1);
    if (!out) { zcio_fail_(ZCIO_ERR_NOMEM, "archive: out of memory"); return NULL; }
    memcpy(out, a->rbuf, a->rlen);
    out[a->rlen] = '\0';
    return out;
}

/* ------------------------------- read ----------------------------------- */

int64_t zcio_archive_read(zcio_archive *a, void *buf, size_t n) {
    if (!a || !buf) return zcio_fail_(ZCIO_ERR_INVALID_ARG, "archive: NULL arg");
    if (a->mode != ZCIO_ARCHIVE_READ)
        return zcio_fail_(ZCIO_ERR_UNSUPPORTED, "archive: read only in read mode");
    if (!a->rbuf) return zcio_fail_(ZCIO_ERR_ARCHIVE, "archive: no active entry");
    if (n == 0) return 0;

    size_t remaining = a->rlen - a->rpos;
    if (remaining == 0) return 0; /* EOF */
    size_t take = n < remaining ? n : remaining;
    memcpy(buf, a->rbuf + a->rpos, take);
    a->rpos += take;
    return (int64_t)take;
}

/* ------------------------------- write ---------------------------------- */

int64_t zcio_archive_write(zcio_archive *a, const void *data, size_t n) {
    if (!a || !data) return zcio_fail_(ZCIO_ERR_INVALID_ARG, "archive: NULL arg");
    if (a->mode != ZCIO_ARCHIVE_WRITE)
        return zcio_fail_(ZCIO_ERR_UNSUPPORTED, "archive: write only in write mode");
    if (!a->entry)
        return zcio_fail_(ZCIO_ERR_ARCHIVE, "archive: no active entry (call set_entry)");
    if (n == 0) return 0;

    if (a->wlen + n > a->wcap) {
        size_t ncap = a->wcap ? a->wcap : 4096;
        while (ncap < a->wlen + n) ncap *= 2;
        char *nb = (char *)realloc(a->wbuf, ncap);
        if (!nb) return zcio_fail_(ZCIO_ERR_NOMEM, "archive: out of memory");
        a->wbuf = nb;
        a->wcap = ncap;
    }
    memcpy(a->wbuf + a->wlen, data, n);
    a->wlen += n;
    return (int64_t)n;
}

#else /* !ZCIO_WITH_ARCHIVE -------------------------------------------------- */

zcio_archive *zcio_archive_open(const char *path, zcio_archive_mode mode) {
    (void)path; (void)mode;
    zcio_fail_(ZCIO_ERR_UNSUPPORTED, "archive: backend not compiled in");
    return NULL;
}

void zcio_archive_close(zcio_archive *a) { (void)a; }

char **zcio_archive_entries(zcio_archive *a, size_t *out_count) {
    (void)a;
    if (out_count) *out_count = 0;
    zcio_fail_(ZCIO_ERR_UNSUPPORTED, "archive: backend not compiled in");
    return NULL;
}

int zcio_archive_set_entry(zcio_archive *a, const char *name) {
    (void)a; (void)name;
    return zcio_fail_(ZCIO_ERR_UNSUPPORTED, "archive: backend not compiled in");
}

char *zcio_archive_entry_string(zcio_archive *a) {
    (void)a;
    zcio_fail_(ZCIO_ERR_UNSUPPORTED, "archive: backend not compiled in");
    return NULL;
}

int64_t zcio_archive_write(zcio_archive *a, const void *data, size_t n) {
    (void)a; (void)data; (void)n;
    return zcio_fail_(ZCIO_ERR_UNSUPPORTED, "archive: backend not compiled in");
}

int64_t zcio_archive_read(zcio_archive *a, void *buf, size_t n) {
    (void)a; (void)buf; (void)n;
    return zcio_fail_(ZCIO_ERR_UNSUPPORTED, "archive: backend not compiled in");
}

#endif /* ZCIO_WITH_ARCHIVE */
