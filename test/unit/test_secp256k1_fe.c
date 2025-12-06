/*
 * Bitcoin Echo — secp256k1 Field Arithmetic Tests
 *
 * Test vectors for field operations modulo p.
 *
 * Build once. Build right. Stop.
 */

#include <stdio.h>
#include <string.h>
#include "secp256k1.h"

static int tests_run = 0;
static int tests_passed = 0;

static void print_hex(const uint8_t *data, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
}

static void print_fe(const secp256k1_fe_t *a)
{
    uint8_t bytes[32];
    secp256k1_fe_get_bytes(bytes, a);
    print_hex(bytes, 32);
}

static int fe_from_hex(secp256k1_fe_t *r, const char *hex)
{
    uint8_t bytes[32];
    int i;

    if (strlen(hex) != 64) {
        return 0;
    }

    for (i = 0; i < 32; i++) {
        unsigned int val;
        if (sscanf(hex + i * 2, "%02x", &val) != 1) {
            return 0;
        }
        bytes[i] = (uint8_t)val;
    }

    return secp256k1_fe_set_bytes(r, bytes);
}

static void test_fe_zero_one(void)
{
    secp256k1_fe_t a, b;

    tests_run++;

    secp256k1_fe_zero(&a);
    secp256k1_fe_one(&b);

    if (secp256k1_fe_is_zero(&a) && !secp256k1_fe_is_zero(&b)) {
        tests_passed++;
        printf("  [PASS] Zero and one\n");
    } else {
        printf("  [FAIL] Zero and one\n");
    }
}

static void test_fe_set_bytes(void)
{
    secp256k1_fe_t a;
    uint8_t bytes[32];
    int valid;

    tests_run++;

    /* Set from valid value */
    valid = fe_from_hex(&a, "0000000000000000000000000000000000000000000000000000000000000001");
    secp256k1_fe_get_bytes(bytes, &a);

    if (valid && bytes[31] == 1) {
        tests_passed++;
        printf("  [PASS] Set bytes (1)\n");
    } else {
        printf("  [FAIL] Set bytes (1)\n");
    }

    tests_run++;

    /* Test value at boundary (p - 1 should be valid) */
    valid = fe_from_hex(&a, "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e");
    if (valid) {
        tests_passed++;
        printf("  [PASS] Set bytes (p-1)\n");
    } else {
        printf("  [FAIL] Set bytes (p-1) - should be valid\n");
    }

    tests_run++;

    /* Test value >= p (should be invalid) */
    valid = fe_from_hex(&a, "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
    if (!valid) {
        tests_passed++;
        printf("  [PASS] Set bytes (p) rejected\n");
    } else {
        printf("  [FAIL] Set bytes (p) - should be invalid\n");
    }
}

static void test_fe_add(void)
{
    secp256k1_fe_t a, b, r, expected;

    tests_run++;

    /* Simple addition: 1 + 2 = 3 */
    secp256k1_fe_set_int(&a, 1);
    secp256k1_fe_set_int(&b, 2);
    secp256k1_fe_add(&r, &a, &b);
    secp256k1_fe_set_int(&expected, 3);

    if (secp256k1_fe_equal(&r, &expected)) {
        tests_passed++;
        printf("  [PASS] Add: 1 + 2 = 3\n");
    } else {
        printf("  [FAIL] Add: 1 + 2 = 3\n");
        printf("    Got: ");
        print_fe(&r);
        printf("\n");
    }

    tests_run++;

    /* Addition wrapping around p */
    /* (p - 1) + 2 = 1 (mod p) */
    fe_from_hex(&a, "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e");
    secp256k1_fe_set_int(&b, 2);
    secp256k1_fe_add(&r, &a, &b);
    secp256k1_fe_set_int(&expected, 1);

    if (secp256k1_fe_equal(&r, &expected)) {
        tests_passed++;
        printf("  [PASS] Add: (p-1) + 2 = 1\n");
    } else {
        printf("  [FAIL] Add: (p-1) + 2 = 1\n");
        printf("    Expected: ");
        print_fe(&expected);
        printf("\n");
        printf("    Got:      ");
        print_fe(&r);
        printf("\n");
    }
}

static void test_fe_sub(void)
{
    secp256k1_fe_t a, b, r, expected;

    tests_run++;

    /* Simple subtraction: 5 - 3 = 2 */
    secp256k1_fe_set_int(&a, 5);
    secp256k1_fe_set_int(&b, 3);
    secp256k1_fe_sub(&r, &a, &b);
    secp256k1_fe_set_int(&expected, 2);

    if (secp256k1_fe_equal(&r, &expected)) {
        tests_passed++;
        printf("  [PASS] Sub: 5 - 3 = 2\n");
    } else {
        printf("  [FAIL] Sub: 5 - 3 = 2\n");
    }

    tests_run++;

    /* Subtraction with wrap: 1 - 2 = p - 1 (mod p) */
    secp256k1_fe_set_int(&a, 1);
    secp256k1_fe_set_int(&b, 2);
    secp256k1_fe_sub(&r, &a, &b);
    fe_from_hex(&expected, "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e");

    if (secp256k1_fe_equal(&r, &expected)) {
        tests_passed++;
        printf("  [PASS] Sub: 1 - 2 = p-1\n");
    } else {
        printf("  [FAIL] Sub: 1 - 2 = p-1\n");
        printf("    Expected: ");
        print_fe(&expected);
        printf("\n");
        printf("    Got:      ");
        print_fe(&r);
        printf("\n");
    }
}

static void test_fe_neg(void)
{
    secp256k1_fe_t a, r, expected;

    tests_run++;

    /* -1 = p - 1 (mod p) */
    secp256k1_fe_set_int(&a, 1);
    secp256k1_fe_neg(&r, &a);
    fe_from_hex(&expected, "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e");

    if (secp256k1_fe_equal(&r, &expected)) {
        tests_passed++;
        printf("  [PASS] Neg: -1 = p-1\n");
    } else {
        printf("  [FAIL] Neg: -1 = p-1\n");
    }

    tests_run++;

    /* -0 = 0 */
    secp256k1_fe_zero(&a);
    secp256k1_fe_neg(&r, &a);

    if (secp256k1_fe_is_zero(&r)) {
        tests_passed++;
        printf("  [PASS] Neg: -0 = 0\n");
    } else {
        printf("  [FAIL] Neg: -0 = 0\n");
    }
}

static void test_fe_mul(void)
{
    secp256k1_fe_t a, b, r, expected;

    tests_run++;

    /* Simple multiplication: 3 * 7 = 21 */
    secp256k1_fe_set_int(&a, 3);
    secp256k1_fe_set_int(&b, 7);
    secp256k1_fe_mul(&r, &a, &b);
    secp256k1_fe_set_int(&expected, 21);

    if (secp256k1_fe_equal(&r, &expected)) {
        tests_passed++;
        printf("  [PASS] Mul: 3 * 7 = 21\n");
    } else {
        printf("  [FAIL] Mul: 3 * 7 = 21\n");
        printf("    Expected: ");
        print_fe(&expected);
        printf("\n");
        printf("    Got:      ");
        print_fe(&r);
        printf("\n");
    }

    tests_run++;

    /* Multiplication by 1 */
    fe_from_hex(&a, "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    secp256k1_fe_one(&b);
    secp256k1_fe_mul(&r, &a, &b);

    if (secp256k1_fe_equal(&r, &a)) {
        tests_passed++;
        printf("  [PASS] Mul: Gx * 1 = Gx\n");
    } else {
        printf("  [FAIL] Mul: Gx * 1 = Gx\n");
    }

    tests_run++;

    /* Multiplication by 0 */
    fe_from_hex(&a, "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    secp256k1_fe_zero(&b);
    secp256k1_fe_mul(&r, &a, &b);

    if (secp256k1_fe_is_zero(&r)) {
        tests_passed++;
        printf("  [PASS] Mul: Gx * 0 = 0\n");
    } else {
        printf("  [FAIL] Mul: Gx * 0 = 0\n");
    }

    tests_run++;

    /* Larger multiplication that requires reduction */
    /* 2^128 * 2^128 = 2^256 ≡ 2^32 + 977 (mod p) */
    fe_from_hex(&a, "0000000000000000000000000000000100000000000000000000000000000000");
    secp256k1_fe_mul(&r, &a, &a);
    /* Expected: 2^32 + 977 = 0x100000000 + 0x3d1 = 0x1000003d1 */
    fe_from_hex(&expected, "00000000000000000000000000000000000000000000000000000001000003d1");

    if (secp256k1_fe_equal(&r, &expected)) {
        tests_passed++;
        printf("  [PASS] Mul: 2^128 * 2^128 = 2^32 + 977\n");
    } else {
        printf("  [FAIL] Mul: 2^128 * 2^128 = 2^32 + 977\n");
        printf("    Expected: ");
        print_fe(&expected);
        printf("\n");
        printf("    Got:      ");
        print_fe(&r);
        printf("\n");
    }
}

static void test_fe_sqr(void)
{
    secp256k1_fe_t a, r, expected;

    tests_run++;

    /* 7² = 49 */
    secp256k1_fe_set_int(&a, 7);
    secp256k1_fe_sqr(&r, &a);
    secp256k1_fe_set_int(&expected, 49);

    if (secp256k1_fe_equal(&r, &expected)) {
        tests_passed++;
        printf("  [PASS] Sqr: 7^2 = 49\n");
    } else {
        printf("  [FAIL] Sqr: 7^2 = 49\n");
    }
}

static void test_fe_inv(void)
{
    secp256k1_fe_t a, inv, product, one;

    tests_run++;

    /* inv(7) * 7 = 1 */
    secp256k1_fe_set_int(&a, 7);
    secp256k1_fe_inv(&inv, &a);
    secp256k1_fe_mul(&product, &inv, &a);
    secp256k1_fe_one(&one);

    if (secp256k1_fe_equal(&product, &one)) {
        tests_passed++;
        printf("  [PASS] Inv: inv(7) * 7 = 1\n");
    } else {
        printf("  [FAIL] Inv: inv(7) * 7 = 1\n");
        printf("    Product: ");
        print_fe(&product);
        printf("\n");
    }

    tests_run++;

    /* inv(Gx) * Gx = 1 */
    fe_from_hex(&a, "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    secp256k1_fe_inv(&inv, &a);
    secp256k1_fe_mul(&product, &inv, &a);

    if (secp256k1_fe_equal(&product, &one)) {
        tests_passed++;
        printf("  [PASS] Inv: inv(Gx) * Gx = 1\n");
    } else {
        printf("  [FAIL] Inv: inv(Gx) * Gx = 1\n");
        printf("    Product: ");
        print_fe(&product);
        printf("\n");
    }
}

static void test_fe_sqrt(void)
{
    secp256k1_fe_t a, root, squared;
    int has_sqrt;

    tests_run++;

    /* sqrt(49) = 7 (or p - 7) */
    secp256k1_fe_set_int(&a, 49);
    has_sqrt = secp256k1_fe_sqrt(&root, &a);
    secp256k1_fe_sqr(&squared, &root);

    if (has_sqrt && secp256k1_fe_equal(&squared, &a)) {
        tests_passed++;
        printf("  [PASS] Sqrt: sqrt(49)^2 = 49\n");
    } else {
        printf("  [FAIL] Sqrt: sqrt(49)^2 = 49\n");
    }

    tests_run++;

    /* Verify Gy² = Gx³ + 7 (curve equation) */
    secp256k1_fe_t gx, gy, gx3, rhs, seven;

    fe_from_hex(&gx, "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    fe_from_hex(&gy, "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8");

    /* Compute Gx³ */
    secp256k1_fe_sqr(&gx3, &gx);      /* Gx² */
    secp256k1_fe_mul(&gx3, &gx3, &gx); /* Gx³ */

    /* Compute Gx³ + 7 */
    secp256k1_fe_set_int(&seven, 7);
    secp256k1_fe_add(&rhs, &gx3, &seven);

    /* Compute Gy² */
    secp256k1_fe_sqr(&a, &gy);

    if (secp256k1_fe_equal(&a, &rhs)) {
        tests_passed++;
        printf("  [PASS] Curve: Gy^2 = Gx^3 + 7\n");
    } else {
        printf("  [FAIL] Curve: Gy^2 = Gx^3 + 7\n");
        printf("    Gy^2:     ");
        print_fe(&a);
        printf("\n");
        printf("    Gx^3 + 7: ");
        print_fe(&rhs);
        printf("\n");
    }
}

int main(void)
{
    printf("secp256k1 Field Arithmetic Tests\n");
    printf("================================\n\n");

    test_fe_zero_one();
    test_fe_set_bytes();
    test_fe_add();
    test_fe_sub();
    test_fe_neg();
    test_fe_mul();
    test_fe_sqr();
    test_fe_inv();
    test_fe_sqrt();

    printf("\n");
    printf("Results: %d/%d tests passed\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
