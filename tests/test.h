/* Copyright Michael A. Penick
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#ifndef TEST_H
#define TEST_H

#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>

typedef struct test_s test_t;
typedef struct test_case_s test_case_t;
typedef struct test_suite_s test_suite_t;

typedef enum { OK, FAILED } test_result_t;

struct test_s {
  const char* name;
  void (*func)(test_case_t*);
  test_result_t result;
  int run;
};

struct test_case_s {
  const char* name;
  void* user_data;
  void (*setup_func)(test_case_t*);
  void (*teardown_func)(test_case_t*);
  test_t tests[128];
};

struct test_suite_s {
  const char* name;
  test_case_t* cases[128];
};

#define TEST(name) static void test_##name##_(test_case_t* test_case_)

#define TEST_ENTRY(name) {#name, test_##name##_, OK, 0},

#define TEST_ENTRY_LAST() \
  { NULL, NULL, OK, 0 }

#define TEST_CASE_SETUP(name) \
  static void test_##name##_setup_(test_case_t* test_case_)

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

#define FATAL(expr)                                                      \
  do {                                                                   \
    if (!(expr)) {                                                       \
      fprintf(stderr, "%s:%d: Fatal:\n%s\n", __FILE__, __LINE__, #expr); \
      fflush(stderr);                                                    \
      abort();                                                           \
    }                                                                    \
  } while (0)

#define ASSERT(expr)                                                       \
  do {                                                                     \
    if (!(expr)) {                                                         \
      fprintf(stderr, "%s:%d: Failure:\n%s\n", __FILE__, __LINE__, #expr); \
      abort();                                                             \
    }                                                                      \
  } while (0)

int test_run_suite_(test_suite_t* suite, int argc, char** argv);

#define TEST_RUN_SUITE(name, argc, argv) \
  test_run_suite_(&test_suite_##name##_, argc, argv)

#endif
