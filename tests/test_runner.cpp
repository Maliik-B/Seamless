// H-17: test runner main(). Walks the auto-registered TestCase list,
// runs each, prints a one-line summary, returns non-zero if any test
// recorded a failure.

#include "test_runner.h"

#include <cstdio>

namespace ds2coop_test {

std::vector<TestCase>& Registry() {
    static std::vector<TestCase> g;
    return g;
}

int& CurrentFailureCount() {
    static int g = 0;
    return g;
}

} // namespace ds2coop_test

int main() {
    auto& tests = ds2coop_test::Registry();
    int passed = 0;
    int failed = 0;

    std::printf("Running %zu test(s)\n", tests.size());
    for (const auto& tc : tests) {
        ds2coop_test::CurrentFailureCount() = 0;
        std::printf("  [%s.%s] ", tc.group, tc.name);
        std::fflush(stdout);
        tc.fn();
        if (ds2coop_test::CurrentFailureCount() == 0) {
            std::printf("ok\n");
            ++passed;
        } else {
            std::printf("FAIL (%d assertion(s))\n", ds2coop_test::CurrentFailureCount());
            ++failed;
        }
    }

    std::printf("\n%d passed, %d failed\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
