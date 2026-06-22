/* zthread.h - a tiny portable thread + sleep shim for the test harness.
 * POSIX uses pthreads; Windows uses the Win32 thread API. Avoids depending on
 * C11 <threads.h>, which is absent from several mainstream libcs (incl. the
 * default macOS toolchain). */
#ifndef ZTHREAD_H
#define ZTHREAD_H

#if defined(_WIN32)
/* Keep <windows.h> from pulling in the legacy <winsock.h>; tests that also
 * include <winsock2.h> (via internal_port.h) would otherwise hit IPPROTO_* and
 * sockaddr_in redefinition errors. */
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#  include <stdlib.h>   /* malloc/free used in the thread trampoline below */

typedef HANDLE zthread_t;
typedef struct { void *(*fn)(void *); void *arg; } zthread_trampoline_;

static DWORD WINAPI zthread_win_entry_(LPVOID p) {
    zthread_trampoline_ *t = (zthread_trampoline_ *)p;
    t->fn(t->arg);
    free(t);
    return 0;
}
static inline int zthread_start(zthread_t *th, void *(*fn)(void *), void *arg) {
    zthread_trampoline_ *t = (zthread_trampoline_ *)malloc(sizeof *t);
    if (!t) return -1;
    t->fn = fn; t->arg = arg;
    *th = CreateThread(NULL, 0, zthread_win_entry_, t, 0, NULL);
    return *th ? 0 : -1;
}
static inline void zthread_join(zthread_t th) {
    WaitForSingleObject(th, INFINITE);
    CloseHandle(th);
}
static inline void zthread_sleep_ms(unsigned ms) { Sleep(ms); }

#else
#  include <pthread.h>
#  include <unistd.h>

typedef pthread_t zthread_t;
static inline int zthread_start(zthread_t *th, void *(*fn)(void *), void *arg) {
    return pthread_create(th, NULL, fn, arg);
}
static inline void zthread_join(zthread_t th) { pthread_join(th, NULL); }
static inline void zthread_sleep_ms(unsigned ms) { usleep(ms * 1000u); }

#endif

#endif /* ZTHREAD_H */
