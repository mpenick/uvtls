#ifndef TEST_H
#define TEST_H

#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <uv.h>

typedef struct test_s test_t;
typedef struct test_case_s test_case_t;
typedef struct test_suite_s test_suite_t;

typedef enum { OK, FAILED } test_result_t;

struct test_s {
  const char* name;
  void (*func)(test_result_t*);
  test_result_t result;
};

struct test_case_s {
  const char* name;
  void* user_data;
  void (*setup_func)(test_case_t*, test_result_t*);
  void (*teardown_func)(test_case_t*);
  test_t tests[128];
};

struct test_suite_s {
  const char* name;
  test_case_t* cases[128];
};

#define TEST(name) static void test_##name##_(test_result_t* result_)

#define TEST_ENTRY(name) {#name, test_##name##_, OK},

#define TEST_ENTRY_LAST() \
  { NULL, NULL, OK }

#define TEST_CASE_SETUP(name)                               \
  static void test_##name##_setup_(test_case_t* test_case_, \
                                   test_result_t* result_)

#define TEST_CASE_TEARDOWN(name) \
  static void test_##name##_teardown_(test_case_t* test_case_)

#define TEST_CASE_DATA() (test_case_->user_data)

#define TEST_CASE_BEGIN(name)             \
  extern test_case_t test_case_##name##_; \
  test_case_t test_case_##name##_ = {#name, NULL, NULL, NULL, {
#define TEST_CASE_BEGIN_EX(name)          \
  extern test_case_t test_case_##name##_; \
  test_case_t test_case_##name##_ = {     \
      #name, NULL, test_##name##_setup_, test_##name##_teardown_, {
#define TEST_CASE_END() \
  }                     \
  }                     \
  ;

#define TEST_CASE_ENTRY(name) &test_case_##name##_,

#define TEST_CASE_ENTRY_LAST() NULL

#define TEST_CASE_EXTERN(name) extern test_case_t test_case_##name##_

#define TEST_SUITE_BEGIN(name) \
  static test_suite_t test_suite_##name##_ = {#name, {
#define TEST_SUITE_END() \
  }                      \
  }                      \
  ;

#define GREEN_(s) "\033[0;32m" s "\033[0m"
#define RED_(s) "\033[0;31m" s "\033[0m"

static uint64_t test_elapsed_ms_(uint64_t start) {
  return (uv_hrtime() - start) / (1000 * 1000);
}

static void test_suite_run_(test_suite_t* suite, FILE* file) {
  int i, ncases = 0, ntests = 0, nfailed = 0, npassed = 0;

  uint64_t start_suite;

  for (i = 0; suite->cases[i]; ++i) {
    int j;
    test_case_t* test_case = suite->cases[i];
    ncases++;
    for (j = 0; test_case->tests[j].name && test_case->tests[j].func; ++j) {
      ntests++;
    }
  }

  fprintf(file,
          GREEN_("[==========]") " Running %d tests from %d test cases.\n",
          ntests,
          ncases);

  start_suite = uv_hrtime();
  for (i = 0; suite->cases[i]; ++i) {
    int j, count = 0;
    uint64_t start_case;
    test_case_t* test_case = suite->cases[i];

    for (j = 0; test_case->tests[j].name && test_case->tests[j].func; ++j) {
      count++;
    }

    fprintf(file,
            GREEN_("[----------]") " %d tests from %s\n",
            count,
            test_case->name);

    start_case = uv_hrtime();
    for (j = 0; test_case->tests[j].name && test_case->tests[j].func; ++j) {
      uint64_t start_test;
      test_t* test = &test_case->tests[j];
      test->result = OK;

      fprintf(file,
              GREEN_("[ %-8s ]") " %s.%s\n",
              "RUN",
              test_case->name,
              test->name);

      start_test = uv_hrtime();
      if (test_case->setup_func) {
        test_case->setup_func(test_case, &test->result);
      }
      if (test->result == OK) {
        test->func(&test->result);
      }
      if (test_case->teardown_func) {
        test_case->teardown_func(test_case);
      }
      if (test->result == FAILED) {
        nfailed++;
        fprintf(file,
                RED_("[ %8s ]") " %s.%s (%lu ms)\n",
                "FAIL",
                test_case->name,
                test->name,
                test_elapsed_ms_(start_test));
      } else {
        npassed++;
        fprintf(file,
                GREEN_("[ %8s ]") " %s.%s (%lu ms)\n",
                "OK",
                test_case->name,
                test->name,
                test_elapsed_ms_(start_test));
      }
    }

    fprintf(file,
            GREEN_("[----------]") " %d tests from %s (%lu ms total)\n\n",
            count,
            test_case->name,
            test_elapsed_ms_(start_case));
  }

  fprintf(
      file,
      GREEN_(
          "[==========]") " %d tests ran from %d test cases. (%lu ms total)\n",
      ntests,
      ncases,
      test_elapsed_ms_(start_suite));

  fprintf(file, GREEN_("[  %s  ]") " %d tests. \n", "PASSED", npassed);
  if (nfailed > 0) {
    fprintf(file,
            RED_("[  %s  ]") " %d test%s, listed below: \n",
            "FAILED",
            nfailed,
            nfailed > 1 ? "s" : "");
    for (i = 0; suite->cases[i]; ++i) {
      int j;
      test_case_t* test_case = suite->cases[i];
      for (j = 0; test_case->tests[j].name && test_case->tests[j].func; ++j) {
        test_t* test = &test_case->tests[j];
        if (test->result == FAILED) {
          fprintf(file,
                  RED_("[  %s  ]") " %s.%s\n",
                  "FAILED",
                  test_case->name,
                  test->name);
        }
      }
    }
  }
}

static void dump_hex_(void* ptr, size_t size) {
  size_t i;
  for (i = 0; i < size; ++i) {
    fprintf(
        stderr, "%s%2x", (i > 0 ? " " : ""), (int) *((const char*) ptr + i));
  }
  fprintf(stderr, "\n");
}

#define FAILURE_LOCATION_() \
  fprintf(stderr, __FILE__ ":%d: Failure\n", __LINE__);

#define FAILURE_(expected, actual, type_format)               \
  FAILURE_LOCATION_()                                         \
  fprintf(stderr,                                             \
          "%10s: %" type_format "\n%10s: %" type_format "\n", \
          "Expected",                                         \
          expected,                                           \
          "Actual",                                           \
          actual);

#define FAILURE_MEM_(expected, actual, size) \
  FAILURE_LOCATION_()                        \
  fprintf(stderr, "%10s: ", "Expected");     \
  dump_hex_(expected, size);                 \
  fprintf(stderr, "%10s: ", "Actual");       \
  dump_hex_(actual, size);

#define ASSERT_(x, ret)               \
  do {                                \
    if (!(x)) {                       \
      FAILURE_("true", "false", "s"); \
      *result_ = FAILED;              \
      if (ret)                        \
        return;                       \
    }                                 \
  } while (0)

#define ASSERT_CMP_(expected, actual, op, type, type_format, ret) \
  do {                                                            \
    type expected_ = (expected);                                  \
    type actual_ = (actual);                                      \
    if (!((type) expected_ op(type) actual_)) {                   \
      FAILURE_(expected_, actual_, type_format);                  \
      if (ret)                                                    \
        return;                                                   \
    }                                                             \
  } while (0)

#define ASSERT_MEMCMP_(expected, actual, size, op, ret) \
  do {                                                  \
    void* expected_ = (expected);                       \
    void* actual_ = (actual);                           \
    size_t size_ = (size);                              \
    if (!(memcmp(expected_, actual_, size_) op 0)) {    \
      FAILURE_MEM_(expected_, actual_, size)            \
      if (ret)                                          \
        return;                                         \
    }                                                   \
  } while (0)

#define ASSERT(x) ASSERT_(x, 1)
#define EXPECT(x) ASSERT_(x, 0)

#define ASSERT_INT_EQ(expected, actual) \
  ASSERT_CMP_(expected, actual, ==, int, "d", 1)
#define EXPECT_INT_EQ(expected, actual) \
  ASSERT_CMP_(expected, actual, ==, int, "d", 0)

#define ASSERT_MEMCMP_EQ(expected, actual, size) \
  ASSERT_MEMCMP_(expected, actual, size, ==, 1)
#define EXPECT_MEMCMP_EQ(expected, actual, size) \
  ASSERT_MEMCMP_(expected, actual, size, ==, 1)

#define TEST_SUITE_RUN(name) test_suite_run_(&test_suite_##name##_, stderr)

#endif
