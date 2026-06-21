/* Archive coverage. Adapts to the build: when libarchive is compiled in
 * (ZCIO_WITH_ARCHIVE) it does a real tar.gz write+read round-trip; otherwise it
 * asserts the stub contract (available()==false, creators fail gracefully). */
#include "ztest.h"
#include "zcio/zcio.h"
#include <stdio.h>

ZTEST(archive_available_contract) {
    bool avail = zcio_archive_available();
    if (!avail) {
        /* stub path: open must fail without crashing */
        zcio_archive *a = zcio_archive_open("/tmp/zcio_none.tar.gz", ZCIO_ARCHIVE_WRITE);
        ZCHECK(a == NULL);
        fprintf(stderr, "  (archive backend not compiled in: stub contract OK)\n");
        return;
    }
    ZCHECK(avail);
}

ZTEST(archive_roundtrip_if_available) {
    if (!zcio_archive_available()) return; /* covered above */

    const char *path = "/tmp/zcio_test_archive.tar.gz";
    zcio_archive *w = zcio_archive_open(path, ZCIO_ARCHIVE_WRITE);
    ZCHECK(w != NULL);
    if (!w) return;
    ZCHECK(zcio_archive_set_entry(w, "hello.txt") == ZCIO_OK);
    const char *payload = "archive payload";
    ZCHECK_EQ(zcio_archive_write(w, payload, 15), 15);
    zcio_archive_close(w);

    zcio_archive *r = zcio_archive_open(path, ZCIO_ARCHIVE_READ);
    ZCHECK(r != NULL);
    if (r) {
        size_t n = 0;
        char **entries = zcio_archive_entries(r, &n);
        ZCHECK(entries != NULL && n >= 1);
        if (entries) {
            int found = 0;
            for (size_t i = 0; i < n; i++) if (strcmp(entries[i], "hello.txt") == 0) found = 1;
            ZCHECK(found);
            zcio_strv_free(entries, n);
        }
        ZCHECK(zcio_archive_set_entry(r, "hello.txt") == ZCIO_OK);
        char *s = zcio_archive_entry_string(r);
        ZCHECK(s != NULL);
        if (s) { ZCHECK(strncmp(s, payload, 15) == 0); zcio_free(s); }
        zcio_archive_close(r);

        /* second open: read the entry via the streaming zcio_archive_read path */
        zcio_archive *r2 = zcio_archive_open(path, ZCIO_ARCHIVE_READ);
        if (r2) {
            ZCHECK(zcio_archive_set_entry(r2, "hello.txt") == ZCIO_OK);
            char rb[32] = {0};
            int64_t got = zcio_archive_read(r2, rb, sizeof rb);
            ZCHECK(got >= 15);
            ZCHECK(strncmp(rb, payload, 15) == 0);
            zcio_archive_close(r2);
        }
    }
    remove(path);
}

ZTEST_MAIN()
