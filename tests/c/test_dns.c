/* DNS / address utility coverage: query_a/aaaa, strv_free, local_ipv4,
 * resolve_ipv4, last_error. */
#include "ztest.h"
#include "zcio/zcio.h"

ZTEST(dns_query_a_localhost) {
    size_t n = 0;
    char **v = zcio_dns_query_a("localhost", &n);
    ZCHECK(v != NULL);
    if (v) {
        ZCHECK(n >= 1);
        int any_v4 = 0;
        for (size_t i = 0; i < n; i++) if (zcio_is_ipv4(v[i])) any_v4 = 1;
        ZCHECK(any_v4);
        zcio_strv_free(v, n);
    }
}

ZTEST(dns_query_aaaa_no_crash) {
    /* may legitimately be empty; must not crash and must return a freeable v */
    size_t n = 0;
    char **v = zcio_dns_query_aaaa("localhost", &n);
    if (v) zcio_strv_free(v, n);
    ZCHECK(1);
}

ZTEST(dns_local_ipv4) {
    char *ip = zcio_local_ipv4();
    /* environment dependent: may be NULL, but if set it should be a v4 literal */
    if (ip) {
        ZCHECK(zcio_is_ipv4(ip));
        zcio_free(ip);
    }
}

ZTEST(dns_resolve_literal) {
    char *ip = zcio_resolve_ipv4("127.0.0.1");
    ZCHECK_STR(ip, "127.0.0.1");
    zcio_free(ip);
}

ZTEST(dns_bad_host_sets_error) {
    char *ip = zcio_resolve_ipv4("no.such.host.invalid.zcio.test.");
    ZCHECK(ip == NULL);
    /* last_error should be non-empty after a failure */
    ZCHECK(zcio_last_error() != NULL);
    if (ip) zcio_free(ip);
}

ZTEST_MAIN()
