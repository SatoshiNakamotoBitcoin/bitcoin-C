/*
 * Bitcoin Echo — secp256k1 Implementation
 *
 * secp256k1 elliptic curve used by Bitcoin.
 *
 * This file implements:
 *   - Field arithmetic (mod p) for Session 2.3
 *   - Group operations (points) for Session 2.4
 *   - ECDSA verification for Session 2.5
 *   - Schnorr verification for Session 2.6
 *
 * The implementation prioritizes correctness over performance.
 * All operations follow the mathematical specifications directly.
 *
 * Build once. Build right. Stop.
 */

#include "secp256k1.h"
#include <string.h>

/*
 * ============================================================================
 * Constants
 * ============================================================================
 */

/*
 * The secp256k1 field prime: p = 2^256 - 2^32 - 977
 *
 * In hex: FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2F
 */
static const uint32_t SECP256K1_P[8] = {
    0xFFFFFC2F, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
};

/*
 * The curve order: n (number of points on curve)
 *
 * In hex: FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141
 */
static const uint32_t SECP256K1_N[8] = {
    0xD0364141, 0xBFD25E8C, 0xAF48A03B, 0xBAAEDCE6,
    0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
};

/*
 * The generator point G (x-coordinate).
 *
 * Gx = 79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B 16F81798
 */
static const uint32_t SECP256K1_GX[8] = {
    0x16F81798, 0x59F2815B, 0x2DCE28D9, 0x029BFCDB,
    0xCE870B07, 0x55A06295, 0xF9DCBBAC, 0x79BE667E
};

/*
 * The generator point G (y-coordinate).
 *
 * Gy = 483ADA77 26A3C465 5DA4FBFC 0E1108A8 FD17B448 A6855419 9C47D08F FB10D4B8
 */
static const uint32_t SECP256K1_GY[8] = {
    0xFB10D4B8, 0x9C47D08F, 0xA6855419, 0xFD17B448,
    0x0E1108A8, 0x5DA4FBFC, 0x26A3C465, 0x483ADA77
};

/*
 * ============================================================================
 * Field Element Operations (mod p)
 * ============================================================================
 */

void secp256k1_fe_zero(secp256k1_fe_t *r)
{
    int i;
    for (i = 0; i < 8; i++) {
        r->limbs[i] = 0;
    }
}

void secp256k1_fe_one(secp256k1_fe_t *r)
{
    r->limbs[0] = 1;
    r->limbs[1] = 0;
    r->limbs[2] = 0;
    r->limbs[3] = 0;
    r->limbs[4] = 0;
    r->limbs[5] = 0;
    r->limbs[6] = 0;
    r->limbs[7] = 0;
}

void secp256k1_fe_set_int(secp256k1_fe_t *r, uint32_t n)
{
    r->limbs[0] = n;
    r->limbs[1] = 0;
    r->limbs[2] = 0;
    r->limbs[3] = 0;
    r->limbs[4] = 0;
    r->limbs[5] = 0;
    r->limbs[6] = 0;
    r->limbs[7] = 0;
}

void secp256k1_fe_copy(secp256k1_fe_t *r, const secp256k1_fe_t *a)
{
    int i;
    for (i = 0; i < 8; i++) {
        r->limbs[i] = a->limbs[i];
    }
}

/*
 * Compare a field element with the prime p.
 * Returns -1 if a < p, 0 if a == p, 1 if a > p.
 */
static int fe_cmp_p(const secp256k1_fe_t *a)
{
    int i;
    for (i = 7; i >= 0; i--) {
        if (a->limbs[i] < SECP256K1_P[i]) return -1;
        if (a->limbs[i] > SECP256K1_P[i]) return 1;
    }
    return 0;
}

/*
 * Reduce field element modulo p if >= p.
 * Subtracts p if necessary.
 */
static void fe_reduce(secp256k1_fe_t *r)
{
    uint64_t borrow;
    uint32_t tmp[8];
    int i;
    int need_reduce;

    /* Check if r >= p */
    need_reduce = (fe_cmp_p(r) >= 0);

    if (need_reduce) {
        /* Subtract p */
        borrow = 0;
        for (i = 0; i < 8; i++) {
            uint64_t diff = (uint64_t)r->limbs[i] - SECP256K1_P[i] - borrow;
            tmp[i] = (uint32_t)diff;
            borrow = (diff >> 63) & 1;  /* 1 if borrow occurred */
        }
        for (i = 0; i < 8; i++) {
            r->limbs[i] = tmp[i];
        }
    }
}

int secp256k1_fe_set_bytes(secp256k1_fe_t *r, const uint8_t bytes[32])
{
    int i, j;

    /* Load big-endian bytes into little-endian limbs */
    for (i = 0; i < 8; i++) {
        j = (7 - i) * 4;
        r->limbs[i] = ((uint32_t)bytes[j] << 24) |
                      ((uint32_t)bytes[j + 1] << 16) |
                      ((uint32_t)bytes[j + 2] << 8) |
                      ((uint32_t)bytes[j + 3]);
    }

    /* Check if value is valid (< p) */
    if (fe_cmp_p(r) >= 0) {
        secp256k1_fe_zero(r);
        return 0;
    }

    return 1;
}

void secp256k1_fe_get_bytes(uint8_t bytes[32], const secp256k1_fe_t *a)
{
    int i, j;

    /* Store little-endian limbs as big-endian bytes */
    for (i = 0; i < 8; i++) {
        j = (7 - i) * 4;
        bytes[j] = (uint8_t)(a->limbs[i] >> 24);
        bytes[j + 1] = (uint8_t)(a->limbs[i] >> 16);
        bytes[j + 2] = (uint8_t)(a->limbs[i] >> 8);
        bytes[j + 3] = (uint8_t)(a->limbs[i]);
    }
}

int secp256k1_fe_is_zero(const secp256k1_fe_t *a)
{
    uint32_t z = 0;
    int i;

    for (i = 0; i < 8; i++) {
        z |= a->limbs[i];
    }

    return z == 0;
}

int secp256k1_fe_equal(const secp256k1_fe_t *a, const secp256k1_fe_t *b)
{
    uint32_t diff = 0;
    int i;

    for (i = 0; i < 8; i++) {
        diff |= a->limbs[i] ^ b->limbs[i];
    }

    return diff == 0;
}

int secp256k1_fe_cmp(const secp256k1_fe_t *a, const secp256k1_fe_t *b)
{
    int i;
    for (i = 7; i >= 0; i--) {
        if (a->limbs[i] < b->limbs[i]) return -1;
        if (a->limbs[i] > b->limbs[i]) return 1;
    }
    return 0;
}

int secp256k1_fe_is_odd(const secp256k1_fe_t *a)
{
    return a->limbs[0] & 1;
}

void secp256k1_fe_neg(secp256k1_fe_t *r, const secp256k1_fe_t *a)
{
    uint64_t borrow;
    int i;

    if (secp256k1_fe_is_zero(a)) {
        secp256k1_fe_zero(r);
        return;
    }

    /* r = p - a */
    borrow = 0;
    for (i = 0; i < 8; i++) {
        uint64_t diff = (uint64_t)SECP256K1_P[i] - a->limbs[i] - borrow;
        r->limbs[i] = (uint32_t)diff;
        borrow = (diff >> 63) & 1;
    }
}

void secp256k1_fe_add(secp256k1_fe_t *r, const secp256k1_fe_t *a, const secp256k1_fe_t *b)
{
    uint64_t carry = 0;
    int i;

    /* Add limbs with carry */
    for (i = 0; i < 8; i++) {
        carry += (uint64_t)a->limbs[i] + b->limbs[i];
        r->limbs[i] = (uint32_t)carry;
        carry >>= 32;
    }

    /* If carry or result >= p, subtract p */
    if (carry || fe_cmp_p(r) >= 0) {
        uint64_t borrow = 0;
        for (i = 0; i < 8; i++) {
            uint64_t diff = (uint64_t)r->limbs[i] - SECP256K1_P[i] - borrow;
            r->limbs[i] = (uint32_t)diff;
            borrow = (diff >> 63) & 1;
        }
    }
}

void secp256k1_fe_sub(secp256k1_fe_t *r, const secp256k1_fe_t *a, const secp256k1_fe_t *b)
{
    uint64_t borrow = 0;
    int i;

    /* Subtract limbs with borrow */
    for (i = 0; i < 8; i++) {
        uint64_t diff = (uint64_t)a->limbs[i] - b->limbs[i] - borrow;
        r->limbs[i] = (uint32_t)diff;
        borrow = (diff >> 63) & 1;
    }

    /* If borrow, add p */
    if (borrow) {
        uint64_t carry = 0;
        for (i = 0; i < 8; i++) {
            carry += (uint64_t)r->limbs[i] + SECP256K1_P[i];
            r->limbs[i] = (uint32_t)carry;
            carry >>= 32;
        }
    }
}

/*
 * Multiply two field elements: r = a * b (mod p)
 *
 * Uses schoolbook multiplication to get a 512-bit product,
 * then reduces modulo p using the special structure of p.
 *
 * p = 2^256 - 2^32 - 977
 * So 2^256 ≡ 2^32 + 977 (mod p)
 */
void secp256k1_fe_mul(secp256k1_fe_t *r, const secp256k1_fe_t *a, const secp256k1_fe_t *b)
{
    uint32_t t[16];  /* 512-bit product as 32-bit limbs */
    uint64_t carry;
    int i, j;

    /* Initialize product to zero */
    for (i = 0; i < 16; i++) {
        t[i] = 0;
    }

    /*
     * Schoolbook multiplication, row by row.
     * Process each a[i] against all b[j], propagating carries.
     * This ensures t[] entries never exceed 32 bits.
     */
    for (i = 0; i < 8; i++) {
        carry = 0;
        for (j = 0; j < 8; j++) {
            uint64_t prod = (uint64_t)a->limbs[i] * b->limbs[j];
            uint64_t sum = (uint64_t)t[i + j] + (prod & 0xFFFFFFFF) + carry;
            t[i + j] = (uint32_t)sum;
            carry = (sum >> 32) + (prod >> 32);
        }
        /* Propagate remaining carry through higher limbs */
        for (j = i + 8; j < 16 && carry; j++) {
            uint64_t sum = (uint64_t)t[j] + carry;
            t[j] = (uint32_t)sum;
            carry = sum >> 32;
        }
    }

    /*
     * Reduce modulo p.
     *
     * We have a 512-bit number t[0..15].
     * t = t_high * 2^256 + t_low
     *
     * Since 2^256 ≡ 2^32 + 977 (mod p):
     * t ≡ t_high * (2^32 + 977) + t_low (mod p)
     *   = t_low + t_high * 2^32 + t_high * 977
     *
     * t_high * 2^32 shifts t_high left by one limb position.
     */
    {
        uint64_t c1, c2, overflow;
        uint32_t low[8], high[8];

        /* Split into low and high 256-bit parts */
        for (i = 0; i < 8; i++) {
            low[i] = t[i];
            high[i] = t[i + 8];
        }

        /* Compute low + high * (2^32 + 977) */
        /* = low + high * 2^32 + high * 977 */

        /* First: low + high * 977 */
        c1 = 0;
        for (i = 0; i < 8; i++) {
            c1 += (uint64_t)low[i] + (uint64_t)high[i] * 977;
            low[i] = (uint32_t)c1;
            c1 >>= 32;
        }
        /* c1 contains overflow from high * 977 (contributes to position 8) */

        /* Now add high * 2^32 (high shifted left by 1 limb) */
        /* low[1..7] += high[0..6], and high[7] goes to position 8 */
        c2 = (uint64_t)low[1] + high[0];
        low[1] = (uint32_t)c2;
        c2 >>= 32;

        c2 += (uint64_t)low[2] + high[1];
        low[2] = (uint32_t)c2;
        c2 >>= 32;

        c2 += (uint64_t)low[3] + high[2];
        low[3] = (uint32_t)c2;
        c2 >>= 32;

        c2 += (uint64_t)low[4] + high[3];
        low[4] = (uint32_t)c2;
        c2 >>= 32;

        c2 += (uint64_t)low[5] + high[4];
        low[5] = (uint32_t)c2;
        c2 >>= 32;

        c2 += (uint64_t)low[6] + high[5];
        low[6] = (uint32_t)c2;
        c2 >>= 32;

        c2 += (uint64_t)low[7] + high[6];
        low[7] = (uint32_t)c2;
        c2 >>= 32;

        /* Position 8 overflow = c1 (from *977) + high[7] + c2 (from shift) */
        overflow = c1 + high[7] + c2;

        /* overflow * 2^256 ≡ overflow * (2^32 + 977) (mod p) */
        /* Add overflow * 977 to low[0..] and overflow to low[1..] */
        while (overflow) {
            uint64_t c3 = (uint64_t)low[0] + overflow * 977;
            low[0] = (uint32_t)c3;
            c3 >>= 32;

            c3 += (uint64_t)low[1] + overflow;
            low[1] = (uint32_t)c3;
            c3 >>= 32;

            for (i = 2; i < 8 && c3; i++) {
                c3 += low[i];
                low[i] = (uint32_t)c3;
                c3 >>= 32;
            }
            overflow = c3;
        }

        /* Copy result */
        for (i = 0; i < 8; i++) {
            r->limbs[i] = low[i];
        }

        /* Final reduction if >= p */
        fe_reduce(r);
    }
}

void secp256k1_fe_sqr(secp256k1_fe_t *r, const secp256k1_fe_t *a)
{
    /* For now, just use multiplication */
    /* A dedicated squaring routine could be ~1.5x faster */
    secp256k1_fe_mul(r, a, a);
}

/*
 * Compute r = a^e (mod p) using square-and-multiply.
 * e is given as an array of 8 uint32_t in little-endian order.
 */
static void fe_pow(secp256k1_fe_t *r, const secp256k1_fe_t *a, const uint32_t e[8])
{
    secp256k1_fe_t base, result, tmp;
    int i, j;

    secp256k1_fe_copy(&base, a);
    secp256k1_fe_one(&result);

    for (i = 0; i < 8; i++) {
        uint32_t word = e[i];
        for (j = 0; j < 32; j++) {
            if (word & 1) {
                secp256k1_fe_mul(&tmp, &result, &base);
                secp256k1_fe_copy(&result, &tmp);
            }
            secp256k1_fe_sqr(&tmp, &base);
            secp256k1_fe_copy(&base, &tmp);
            word >>= 1;
        }
    }

    secp256k1_fe_copy(r, &result);
}

/*
 * Invert field element: r = a^(-1) (mod p)
 *
 * Uses Fermat's little theorem: a^(-1) = a^(p-2) (mod p)
 *
 * p - 2 = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2D
 */
void secp256k1_fe_inv(secp256k1_fe_t *r, const secp256k1_fe_t *a)
{
    static const uint32_t P_MINUS_2[8] = {
        0xFFFFFC2D, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
    };

    fe_pow(r, a, P_MINUS_2);
}

/*
 * Compute square root: r = sqrt(a) (mod p), if it exists.
 *
 * Since p ≡ 3 (mod 4), we can use: sqrt(a) = a^((p+1)/4) (mod p)
 *
 * (p + 1) / 4 = 3FFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF BFFFFF0C
 */
int secp256k1_fe_sqrt(secp256k1_fe_t *r, const secp256k1_fe_t *a)
{
    static const uint32_t P_PLUS_1_DIV_4[8] = {
        0xBFFFFF0C, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x3FFFFFFF
    };

    secp256k1_fe_t candidate, check;

    /* Compute candidate = a^((p+1)/4) */
    fe_pow(&candidate, a, P_PLUS_1_DIV_4);

    /* Verify: candidate² should equal a */
    secp256k1_fe_sqr(&check, &candidate);

    if (!secp256k1_fe_equal(&check, a)) {
        /* No square root exists */
        secp256k1_fe_zero(r);
        return 0;
    }

    /* Return the "even" square root (LSB = 0) */
    if (secp256k1_fe_is_odd(&candidate)) {
        secp256k1_fe_neg(r, &candidate);
    } else {
        secp256k1_fe_copy(r, &candidate);
    }

    return 1;
}

/*
 * ============================================================================
 * Scalar Operations (mod n)
 * ============================================================================
 */

/*
 * Compare a scalar with n.
 */
static int scalar_cmp_n(const secp256k1_scalar_t *a)
{
    int i;
    for (i = 7; i >= 0; i--) {
        if (a->limbs[i] < SECP256K1_N[i]) return -1;
        if (a->limbs[i] > SECP256K1_N[i]) return 1;
    }
    return 0;
}

/*
 * Reduce scalar modulo n if >= n.
 */
static void scalar_reduce(secp256k1_scalar_t *r)
{
    uint64_t borrow;
    uint32_t tmp[8];
    int i;

    if (scalar_cmp_n(r) >= 0) {
        borrow = 0;
        for (i = 0; i < 8; i++) {
            uint64_t diff = (uint64_t)r->limbs[i] - SECP256K1_N[i] - borrow;
            tmp[i] = (uint32_t)diff;
            borrow = (diff >> 63) & 1;
        }
        for (i = 0; i < 8; i++) {
            r->limbs[i] = tmp[i];
        }
    }
}

void secp256k1_scalar_set_bytes(secp256k1_scalar_t *r, const uint8_t bytes[32])
{
    int i, j;

    /* Load big-endian bytes into little-endian limbs */
    for (i = 0; i < 8; i++) {
        j = (7 - i) * 4;
        r->limbs[i] = ((uint32_t)bytes[j] << 24) |
                      ((uint32_t)bytes[j + 1] << 16) |
                      ((uint32_t)bytes[j + 2] << 8) |
                      ((uint32_t)bytes[j + 3]);
    }

    /* Reduce if >= n */
    scalar_reduce(r);
}

void secp256k1_scalar_get_bytes(uint8_t bytes[32], const secp256k1_scalar_t *a)
{
    int i, j;

    for (i = 0; i < 8; i++) {
        j = (7 - i) * 4;
        bytes[j] = (uint8_t)(a->limbs[i] >> 24);
        bytes[j + 1] = (uint8_t)(a->limbs[i] >> 16);
        bytes[j + 2] = (uint8_t)(a->limbs[i] >> 8);
        bytes[j + 3] = (uint8_t)(a->limbs[i]);
    }
}

int secp256k1_scalar_is_zero(const secp256k1_scalar_t *a)
{
    uint32_t z = 0;
    int i;

    for (i = 0; i < 8; i++) {
        z |= a->limbs[i];
    }

    return z == 0;
}

/*
 * ============================================================================
 * Point Operations (to be completed in Session 2.4)
 * ============================================================================
 */

void secp256k1_point_set_infinity(secp256k1_point_t *r)
{
    secp256k1_fe_zero(&r->x);
    secp256k1_fe_zero(&r->y);
    secp256k1_fe_zero(&r->z);
}

int secp256k1_point_is_infinity(const secp256k1_point_t *p)
{
    return secp256k1_fe_is_zero(&p->z);
}

void secp256k1_point_set_xy(secp256k1_point_t *r,
                            const secp256k1_fe_t *x,
                            const secp256k1_fe_t *y)
{
    secp256k1_fe_copy(&r->x, x);
    secp256k1_fe_copy(&r->y, y);
    secp256k1_fe_one(&r->z);
}

void secp256k1_point_get_xy(secp256k1_fe_t *x, secp256k1_fe_t *y,
                            const secp256k1_point_t *p)
{
    secp256k1_fe_t z_inv, z_inv2, z_inv3;

    /* Convert from Jacobian (X, Y, Z) to affine (X/Z², Y/Z³) */
    secp256k1_fe_inv(&z_inv, &p->z);
    secp256k1_fe_sqr(&z_inv2, &z_inv);
    secp256k1_fe_mul(&z_inv3, &z_inv2, &z_inv);

    if (x) {
        secp256k1_fe_mul(x, &p->x, &z_inv2);
    }
    if (y) {
        secp256k1_fe_mul(y, &p->y, &z_inv3);
    }
}

/* Point operations will be implemented in Session 2.4 */
void secp256k1_point_double(secp256k1_point_t *r, const secp256k1_point_t *p)
{
    (void)r; (void)p;
    /* TODO: Session 2.4 */
}

void secp256k1_point_add(secp256k1_point_t *r,
                         const secp256k1_point_t *p,
                         const secp256k1_point_t *q)
{
    (void)r; (void)p; (void)q;
    /* TODO: Session 2.4 */
}

void secp256k1_point_mul(secp256k1_point_t *r,
                         const secp256k1_point_t *p,
                         const secp256k1_scalar_t *k)
{
    (void)r; (void)p; (void)k;
    /* TODO: Session 2.4 */
}

void secp256k1_point_mul_gen(secp256k1_point_t *r, const secp256k1_scalar_t *k)
{
    (void)r; (void)k;
    /* TODO: Session 2.4 */
}

int secp256k1_point_is_valid(const secp256k1_point_t *p)
{
    (void)p;
    /* TODO: Session 2.4 */
    return 0;
}

void secp256k1_point_neg(secp256k1_point_t *r, const secp256k1_point_t *p)
{
    (void)r; (void)p;
    /* TODO: Session 2.4 */
}

int secp256k1_pubkey_parse(secp256k1_point_t *p, const uint8_t *data, size_t len)
{
    (void)p; (void)data; (void)len;
    /* TODO: Session 2.4 */
    return 0;
}

void secp256k1_pubkey_serialize(uint8_t *out, const secp256k1_point_t *p, int compressed)
{
    (void)out; (void)p; (void)compressed;
    /* TODO: Session 2.4 */
}
