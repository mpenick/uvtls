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

#include "test.h"

#include <inttypes.h>

#ifdef _WIN32
#define GREEN_(s) s
#define RED_(s) s
#else
#define GREEN_(s) "\033[0;32m" s "\033[0m"
#define RED_(s) "\033[0;31m" s "\033[0m"
#endif

static int match(const char* p, const char* s) {
  size_t px = 0, next_px = 0, sx = 0, next_sx = 0;
  size_t plen = strlen(p), slen = strlen(s);

  while (px < plen || sx < slen) {
    char c = p[px];
    switch (c) {
      default:
        if (sx < slen && s[sx] == c) {
          px++;
          sx++;
          continue;
        }
        break;
      case '?':
        if (sx < slen) {
          px++;
          sx++;
          continue;
        }
        break;
      case '*':
        next_px = px;
        next_sx = sx + 1;
        px++;
        continue;
    }
    if (0 < next_sx && next_sx <= slen) {
      px = next_px;
      sx = next_sx;
      continue;
    }
    return 0;
  }

  return 1;
}

static int test_match(const char* p,
                      const char* test_case_name,
                      const char* test_name) {
  char full_test_name[512];
  snprintf(full_test_name,
           sizeof(full_test_name),
           "%s.%s",
           test_case_name,
           test_name);
  return match(p, full_test_name);
}

static void print_help(const char* prog) {
  fprintf(stderr, "%s [-f|--filter <pattern>]", prog);
}

static int parse_options(int argc,
                         char** argv,
                         const char** filter,
                         const char** single_test_case_name,
                         const char** single_test_name) {
  int i;
  int noptions = 0;
  for (i = 1; i < argc; ++i) {
    char* arg = argv[i];
    if (strstr(arg, "-f") || strstr(arg, "--filter")) {
      if (i + 1 >= argc) {
        print_help(argv[0]);
        return -1;
      }
      *filter = argv[++i];
      noptions++;
    } else if (strstr(arg, "-t") || strstr(arg, "--single-test")) {
      if (i + 2 >= argc) {
        print_help(argv[0]);
        return -1;
      }
      *single_test_case_name = argv[++i];
      *single_test_name = argv[++i];
      noptions++;
    }
  }
  return noptions;
}

static uint64_t test_elapsed_ms(uint64_t start) {
  return (uv_hrtime() - start) / (1000 * 1000);
}


typedef struct {
  int64_t exit_status;
  int term_signal;
} test_process_result_t;

static void on_process_exit(uv_process_t* req,
                            int64_t exit_status,
                            int term_signal) {
  test_process_result_t* result = (test_process_result_t*) req->data;
  result->exit_status = exit_status;
  result->term_signal = term_signal;
}

static test_result_t test_run_in_process(const char* program_name,
                                         const char* test_case_name,
                                         const char* test_name) {
  int rc;
  uv_process_t process;
  uv_process_options_t options = {0};
  uv_stdio_container_t child_stdio[3];
  test_process_result_t result = {0};


  char* args[5];
  args[0] = (char*) program_name;
  args[1] = "--single-test";
  args[2] = (char*) test_case_name;
  args[3] = (char*) test_name;
  args[4] = NULL;

  options.stdio_count = 3;
  child_stdio[0].flags = UV_IGNORE;
  child_stdio[1].flags = UV_INHERIT_FD;
  child_stdio[1].data.fd = 1;
  child_stdio[2].flags = UV_INHERIT_FD;
  child_stdio[2].data.fd = 2;
  options.stdio = child_stdio;

  options.file = program_name;
  options.args = args;
  options.exit_cb = on_process_exit;

  process.data = &result;
  rc = uv_spawn(uv_default_loop(), &process, &options);
  if (rc != 0) {
    return FAILED;
  }

  uv_run(uv_default_loop(), UV_RUN_DEFAULT);

  if (result.exit_status != 0) {
    return FAILED;
  }

  if (result.term_signal != 0) {
    if (result.term_signal != SIGABRT) {
      fprintf(stderr, "Process exited with signal %d\n", result.term_signal);
    }
    return FAILED;
  }

  return OK;
}

static int test_single_run(test_suite_t* suite,
                           const char* test_case_name,
                           const char* test_name) {
  int i;
  for (i = 0; suite->cases[i]; ++i) {
    int j;
    test_case_t* test_case = suite->cases[i];
    if (strcmp(test_case_name, test_case->name) != 0) {
      continue;
    }
    for (j = 0; test_case->tests[j].name && test_case->tests[j].func; ++j) {
      test_t* test = &test_case->tests[j];
      if (strcmp(test_name, test->name) == 0) {
        if (test_case->setup_func) {
          test_case->setup_func(test_case);
        }
        test->func(test_case);
        if (test_case->teardown_func) {
          test_case->teardown_func(test_case);
        }
        return 0;
      }
    }
  }
  return 1;
}

int test_run_suite_(test_suite_t* suite, int argc, char** argv) {
  int i, ncases = 0, ntests = 0, nfailed = 0, npassed = 0;
  const char* filter = "*";
  const char* single_test_case_name = NULL;
  const char* single_test_name = NULL;
  uint64_t start_suite;

  if (parse_options(
          argc, argv, &filter, &single_test_case_name, &single_test_name) <
      0) {
    return 1;
  }

  if (single_test_case_name || single_test_name) {
    return test_single_run(suite, single_test_case_name, single_test_name);
  }

  for (i = 0; suite->cases[i]; ++i) {
    int j;
    test_case_t* test_case = suite->cases[i];
    ncases++;
    for (j = 0; test_case->tests[j].name && test_case->tests[j].func; ++j) {
      test_t* test = &test_case->tests[j];
      if (test_match(filter, test_case->name, test->name)) {
        test->run = 1;
        ntests++;
      }
    }
  }

  fprintf(stderr,
          GREEN_("[==========]") " Running %d tests from %d test cases.\n",
          ntests,
          ncases);

  start_suite = uv_hrtime();
  for (i = 0; suite->cases[i]; ++i) {
    int j, count = 0;
    uint64_t start_case;
    test_case_t* test_case = suite->cases[i];

    for (j = 0; test_case->tests[j].name && test_case->tests[j].func; ++j) {
      test_t* test = &test_case->tests[j];
      if (test->run) count++;
    }

    fprintf(stderr,
            GREEN_("[----------]") " %d tests from %s\n",
            count,
            test_case->name);

    start_case = uv_hrtime();
    for (j = 0; test_case->tests[j].name && test_case->tests[j].func; ++j) {
      uint64_t start_test;
      test_t* test = &test_case->tests[j];

      if (!test->run) continue;

      fprintf(stderr,
              GREEN_("[ %-8s ]") " %s.%s\n",
              "RUN",
              test_case->name,
              test->name);

      start_test = uv_hrtime();
      test->result = test_run_in_process(argv[0], test_case->name, test->name);

      if (test->result == OK) {
        npassed++;
      } else {
        nfailed++;
      }

      fprintf(stderr,
              test->result == OK ? GREEN_("[ %8s ]") " %s.%s (%" PRIu64 " ms)\n"
                                 : RED_("[ %8s ]") " %s.%s (%" PRIu64 " ms)\n",
              test->result == OK ? "OK" : "FAILED",
              test_case->name,
              test->name,
              test_elapsed_ms(start_test));
    }

    fprintf(stderr,
            GREEN_("[----------]") " %d tests from %s (%" PRIu64 " ms total)\n",
            count,
            test_case->name,
            test_elapsed_ms(start_case));
  }

  fprintf(
      stderr,
      GREEN_("[==========]") " %d tests ran from %d test cases. (%" PRIu64 " ms total)\n",
      ntests,
      ncases,
      test_elapsed_ms(start_suite));

  fprintf(stderr, GREEN_("[  %s  ]") " %d tests. \n", "PASSED", npassed);
  if (nfailed > 0) {
    fprintf(stderr,
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
          fprintf(stderr,
                  RED_("[  %s  ]") " %s.%s\n",
                  "FAILED",
                  test_case->name,
                  test->name);
        }
      }
    }
  }

  return nfailed > 0;
}
