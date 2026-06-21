/* Port of ip_validation_tests.cpp / utility_tests.cpp essentials. */
#include "ztest.h"
#include "zcio/zcio.h"

ZTEST(ipv4_validation) {
    ZCHECK(zcio_is_ipv4("127.0.0.1"));
    ZCHECK(zcio_is_ipv4("255.255.255.255"));
    ZCHECK(zcio_is_ipv4("0.0.0.0"));
    ZCHECK(!zcio_is_ipv4("256.0.0.1"));
    ZCHECK(!zcio_is_ipv4("1.2.3"));
    ZCHECK(!zcio_is_ipv4("hello"));
    ZCHECK(!zcio_is_ipv4("1.2.3.4.5"));
}

ZTEST(resolve_literal_passthrough) {
    char *ip = zcio_resolve_ipv4("8.8.8.8");
    ZCHECK_STR(ip, "8.8.8.8");
    zcio_free(ip);
}

ZTEST(version_reported) {
    int a = -1, b = -1, c = -1;
    zcio_version(&a, &b, &c);
    ZCHECK(a >= 0 && b >= 0 && c >= 0);
    ZCHECK(zcio_version_string() != NULL);
}

ZTEST(result_strings) {
    ZCHECK_STR(zcio_result_str(ZCIO_OK), "ok");
    ZCHECK(strlen(zcio_result_str(ZCIO_ERR_TIMEOUT)) > 0);
}

ZTEST_MAIN()
