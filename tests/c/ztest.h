/* ztest.h - a ~zero-dependency C test microframework for zcio.
 * Each test file defines tests with ZTEST(name){...} and ends with ZTEST_MAIN().
 * Assertions record a failure and continue within a test; a failing test makes
 * the process exit non-zero so CTest flags it. */
#ifndef ZTEST_H
#define ZTEST_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

typedef void (*ztest_fn)(void);
typedef struct { const char *name; ztest_fn fn; } ztest_case;

#ifndef ZTEST_MAX
#  define ZTEST_MAX 256
#endif

static ztest_case ztest_cases_[ZTEST_MAX];
static int        ztest_count_   = 0;
static int        ztest_fails_   = 0;   /* failures in the current test */
static int        ztest_total_fails_ = 0;
static const char *ztest_cur_ = "";

#define ZTEST(NAME)                                                        \
    static void NAME(void);                                                \
    __attribute__((constructor)) static void ztest_reg_##NAME(void) {      \
        ztest_cases_[ztest_count_].name = #NAME;                           \
        ztest_cases_[ztest_count_].fn = NAME;                              \
        ztest_count_++;                                                    \
    }                                                                      \
    static void NAME(void)

#define ZCHECK(COND) do {                                                  \
        if (!(COND)) {                                                     \
            ztest_fails_++;                                                \
            fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #COND); \
        }                                                                  \
    } while (0)

#define ZCHECK_EQ(A, B) do {                                              \
        long long a_ = (long long)(A), b_ = (long long)(B);               \
        if (a_ != b_) {                                                    \
            ztest_fails_++;                                                \
            fprintf(stderr, "  FAIL %s:%d: %s (%lld) == %s (%lld)\n",      \
                    __FILE__, __LINE__, #A, a_, #B, b_);                   \
        }                                                                  \
    } while (0)

#define ZCHECK_STR(A, B) do {                                             \
        const char *a_ = (A), *b_ = (B);                                  \
        if (!a_ || !b_ || strcmp(a_, b_) != 0) {                          \
            ztest_fails_++;                                                \
            fprintf(stderr, "  FAIL %s:%d: \"%s\" == \"%s\"\n",            \
                    __FILE__, __LINE__, a_ ? a_ : "(null)", b_ ? b_ : "(null)"); \
        }                                                                  \
    } while (0)

#define ZTEST_MAIN()                                                       \
    int main(void) {                                                       \
        for (int i = 0; i < ztest_count_; i++) {                          \
            ztest_fails_ = 0;                                              \
            ztest_cur_ = ztest_cases_[i].name;                            \
            ztest_cases_[i].fn();                                         \
            if (ztest_fails_) {                                           \
                ztest_total_fails_++;                                     \
                fprintf(stderr, "[FAIL] %s\n", ztest_cur_);              \
            } else {                                                      \
                fprintf(stderr, "[ ok ] %s\n", ztest_cur_);             \
            }                                                             \
        }                                                                 \
        fprintf(stderr, "%d/%d tests passed\n",                          \
                ztest_count_ - ztest_total_fails_, ztest_count_);         \
        return ztest_total_fails_ ? 1 : 0;                               \
    }

#endif /* ZTEST_H */
