/* zcio/dns.h - name resolution and address utilities.
 *
 * Ports system_dns, string_is_ipv4, resolve_host_or_ip_to_ip, get_local_ip.
 * Resolution is syscall-bound (getaddrinfo) and therefore not O(1); everything
 * else here is constant-time string work.
 */
#ifndef ZCIO_DNS_H
#define ZCIO_DNS_H

#include "zcio/types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* True if `s` is a dotted-quad IPv4 literal. */
ZCIO_API bool zcio_is_ipv4(const char *s);

/* Resolve `host` (name or literal) to an IPv4 string. Caller frees with
 * zcio_free. Returns NULL on failure. */
ZCIO_API char *zcio_resolve_ipv4(const char *host);

/* Resolve all A (family AF_INET) or AAAA (AF_INET6) records. Returns a
 * NULL-terminated, malloc'd array of malloc'd strings; free with
 * zcio_strv_free. *out_count receives the count (may be NULL). */
ZCIO_API char **zcio_dns_query_a   (const char *host, size_t *out_count);
ZCIO_API char **zcio_dns_query_aaaa(const char *host, size_t *out_count);
ZCIO_API void   zcio_strv_free(char **v, size_t count);

/* Best-effort primary local IPv4 (UDP-connect-to-8.8.8.8 trick). Caller frees. */
ZCIO_API char *zcio_local_ipv4(void);

#ifdef __cplusplus
}
#endif

#endif /* ZCIO_DNS_H */
