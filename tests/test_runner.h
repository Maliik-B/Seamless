#pragma once

// H-17: tiny home-rolled test runner. Each TEST(group, name) auto-registers
// itself via a file-static initializer — main() walks the registry. Zero
// deps. Resist the urge to grow this into a framework.

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

namespace ds2coop_test {

using TestFn = void (*)();

struct TestCase {
    const char* group;
    const char* name;
    TestFn      fn;
};

// Defined in test_runner.cpp.
std::vector<TestCase>& Registry();

struct AutoReg {
    AutoReg(const char* group, const char* name, TestFn fn) {
        Registry().push_back({group, name, fn});
    }
};

// Per-test failure counter (reset before each test by the runner).
int& CurrentFailureCount();

inline void ReportFailure(const char* file, int line, const char* expr) {
    ++CurrentFailureCount();
    std::fprintf(stderr, "  FAIL  %s:%d  %s\n", file, line, expr);
}

} // namespace ds2coop_test

#define TEST(group_, name_)                                                       \
    static void test_##group_##_##name_();                                        \
    static ::ds2coop_test::AutoReg s_reg_##group_##_##name_(                      \
        #group_, #name_, &test_##group_##_##name_);                               \
    static void test_##group_##_##name_()

#define ASSERT_TRUE(cond)                                                         \
    do {                                                                          \
        if (!(cond)) ::ds2coop_test::ReportFailure(__FILE__, __LINE__, #cond);    \
    } while (0)

#define ASSERT_FALSE(cond) ASSERT_TRUE(!(cond))

#define ASSERT_EQ(a, b)                                                           \
    do {                                                                          \
        auto _a = (a); auto _b = (b);                                             \
        if (!(_a == _b))                                                          \
            ::ds2coop_test::ReportFailure(__FILE__, __LINE__, #a " == " #b);      \
    } while (0)

#define ASSERT_NE(a, b)                                                           \
    do {                                                                          \
        auto _a = (a); auto _b = (b);                                             \
        if (!(_a != _b))                                                          \
            ::ds2coop_test::ReportFailure(__FILE__, __LINE__, #a " != " #b);      \
    } while (0)
