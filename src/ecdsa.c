#include "ecdsa.h"
#include <string.h>

/*
 * Parametros oficiales NIST SP 800-186 para Curve P-256 (secp256r1)
 */
static const char *P256_P_HEX = "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF";
static const char *P256_A_HEX = "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC";
static const char *P256_B_HEX = "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B";
static const char *P256_GX_HEX = "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296";
static const char *P256_GY_HEX = "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5";
static const char *P256_N_HEX = "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551";

void ec_init_p256(ECCurve *curve) {
    bigint_from_hex(&curve->p, P256_P_HEX);
    bigint_from_hex(&curve->a, P256_A_HEX);
    bigint_from_hex(&curve->b, P256_B_HEX);
    bigint_from_hex(&curve->n, P256_N_HEX);

    bigint_from_hex(&curve->G.x, P256_GX_HEX);
    bigint_from_hex(&curve->G.y, P256_GY_HEX);
    curve->G.is_infinity = 0;
}

int ecdsa_point_is_on_curve(const ECCurve *curve, const ECPoint *P) {
    if (P->is_infinity) return 1;

    /* Verifica lhs = y^2 mod p */
    BigInt lhs;
    bigint_mul_mod(&lhs, &P->y, &P->y, &curve->p);

    /* Verifica rhs = (x^3 + a*x + b) mod p */
    BigInt x2, x3, ax, rhs;
    bigint_mul_mod(&x2, &P->x, &P->x, &curve->p);
    bigint_mul_mod(&x3, &x2, &P->x, &curve->p);
    bigint_mul_mod(&ax, &curve->a, &P->x, &curve->p);
    bigint_add_mod(&rhs, &x3, &ax, &curve->p);
    bigint_add_mod(&rhs, &rhs, &curve->b, &curve->p);

    return (bigint_cmp(&lhs, &rhs) == 0);
}

void ec_point_double(const ECCurve *curve, const ECPoint *P, ECPoint *R) {
    if (P->is_infinity || bigint_is_zero(&P->y)) {
        R->is_infinity = 1;
        bigint_zero(&R->x);
        bigint_zero(&R->y);
        return;
    }

    BigInt x1 = P->x;
    BigInt y1 = P->y;

    /* lambda = (3*x1^2 + a) * (2*y1)^(-1) mod p */
    BigInt x1_sq, three, num, den, inv_den, lambda;
    bigint_mul_mod(&x1_sq, &x1, &x1, &curve->p);
    bigint_set_u32(&three, 3);
    bigint_mul_mod(&num, &x1_sq, &three, &curve->p);
    bigint_add_mod(&num, &num, &curve->a, &curve->p);

    BigInt two;
    bigint_set_u32(&two, 2);
    bigint_mul_mod(&den, &y1, &two, &curve->p);

    if (!bigint_inv_mod(&inv_den, &den, &curve->p)) {
        R->is_infinity = 1;
        return;
    }
    bigint_mul_mod(&lambda, &num, &inv_den, &curve->p);

    /* x3 = (lambda^2 - 2*x1) mod p */
    BigInt lambda_sq, two_x1, x3;
    bigint_mul_mod(&lambda_sq, &lambda, &lambda, &curve->p);
    bigint_add_mod(&two_x1, &x1, &x1, &curve->p);
    bigint_sub_mod(&x3, &lambda_sq, &two_x1, &curve->p);

    /* y3 = (lambda*(x1 - x3) - y1) mod p */
    BigInt x_diff, y3;
    bigint_sub_mod(&x_diff, &x1, &x3, &curve->p);
    bigint_mul_mod(&y3, &lambda, &x_diff, &curve->p);
    bigint_sub_mod(&y3, &y3, &y1, &curve->p);

    R->x = x3;
    R->y = y3;
    R->is_infinity = 0;
}

void ec_point_add(const ECCurve *curve, const ECPoint *P, const ECPoint *Q, ECPoint *R) {
    if (P->is_infinity) {
        *R = *Q;
        return;
    }
    if (Q->is_infinity) {
        *R = *P;
        return;
    }

    if (bigint_cmp(&P->x, &Q->x) == 0) {
        if (bigint_cmp(&P->y, &Q->y) == 0) {
            ec_point_double(curve, P, R);
            return;
        } else {
            /* P + (-P) = O */
            R->is_infinity = 1;
            bigint_zero(&R->x);
            bigint_zero(&R->y);
            return;
        }
    }

    BigInt x1 = P->x;
    BigInt y1 = P->y;
    BigInt x2 = Q->x;
    BigInt y2 = Q->y;

    /* lambda = (y2 - y1) * (x2 - x1)^(-1) mod p */
    BigInt dy, dx, inv_dx, lambda;
    bigint_sub_mod(&dy, &y2, &y1, &curve->p);
    bigint_sub_mod(&dx, &x2, &x1, &curve->p);

    if (!bigint_inv_mod(&inv_dx, &dx, &curve->p)) {
        R->is_infinity = 1;
        return;
    }
    bigint_mul_mod(&lambda, &dy, &inv_dx, &curve->p);

    /* x3 = (lambda^2 - x1 - x2) mod p */
    BigInt lambda_sq, sum_x, x3;
    bigint_mul_mod(&lambda_sq, &lambda, &lambda, &curve->p);
    bigint_add_mod(&sum_x, &x1, &x2, &curve->p);
    bigint_sub_mod(&x3, &lambda_sq, &sum_x, &curve->p);

    /* y3 = (lambda*(x1 - x3) - y1) mod p */
    BigInt x_diff, y3;
    bigint_sub_mod(&x_diff, &x1, &x3, &curve->p);
    bigint_mul_mod(&y3, &lambda, &x_diff, &curve->p);
    bigint_sub_mod(&y3, &y3, &y1, &curve->p);

    R->x = x3;
    R->y = y3;
    R->is_infinity = 0;
}

void ec_scalar_mul(const ECCurve *curve, const BigInt k, const ECPoint *P, ECPoint *R) {
    if (bigint_is_zero(&k) || P->is_infinity) {
        R->is_infinity = 1;
        bigint_zero(&R->x);
        bigint_zero(&R->y);
        return;
    }

    ECPoint acc;
    acc.is_infinity = 1;
    bigint_zero(&acc.x);
    bigint_zero(&acc.y);

    int bit_len = bigint_bit_length(&k);
    for (int i = bit_len - 1; i >= 0; i--) {
        if (!acc.is_infinity) {
            ec_point_double(curve, &acc, &acc);
        }
        if (bigint_get_bit(&k, i)) {
            if (acc.is_infinity) {
                acc = *P;
            } else {
                ec_point_add(curve, &acc, P, &acc);
            }
        }
    }
    *R = acc;
}

int ecdsa_keygen(const ECCurve *curve, BigInt priv_d, ECPoint *pub_Q) {
    /* Validar que 1 <= d <= n - 1 */
    BigInt one, n_minus_1;
    bigint_set_u32(&one, 1);
    bigint_sub(&n_minus_1, &curve->n, &one);

    if (bigint_cmp(&priv_d, &one) < 0 || bigint_cmp(&priv_d, &n_minus_1) > 0) {
        return 0;
    }

    /* Q = [d]G */
    ec_scalar_mul(curve, priv_d, &curve->G, pub_Q);
    if (pub_Q->is_infinity) return 0;
    if (!ecdsa_point_is_on_curve(curve, pub_Q)) return 0;

    return 1;
}

int ecdsa_generate_keypair(const ECCurve *curve, BigInt *priv_d, ECPoint *pub_Q) {
    BigInt one, n_minus_1;
    bigint_set_u32(&one, 1);
    bigint_sub(&n_minus_1, &curve->n, &one);

    if (!bigint_random_range(priv_d, &one, &n_minus_1)) {
        return 0;
    }
    return ecdsa_keygen(curve, *priv_d, pub_Q);
}

int ecdsa_sign_with_k(const ECCurve *curve, const BigInt priv_d, const BigInt hash_e, const BigInt k, ECDSASignature *sig) {
    BigInt one, n_minus_1;
    bigint_set_u32(&one, 1);
    bigint_sub(&n_minus_1, &curve->n, &one);

    /* Validar d y k en [1, n - 1] */
    if (bigint_cmp(&priv_d, &one) < 0 || bigint_cmp(&priv_d, &n_minus_1) > 0) return 0;
    if (bigint_cmp(&k, &one) < 0 || bigint_cmp(&k, &n_minus_1) > 0) return 0;

    /* (x1, y1) = [k]G */
    ECPoint kG;
    ec_scalar_mul(curve, k, &curve->G, &kG);
    if (kG.is_infinity) return 0;

    /* r = x1 mod n */
    BigInt r;
    bigint_mod(&r, &kG.x, &curve->n);
    if (bigint_is_zero(&r)) return 0;

    /* k^(-1) mod n */
    BigInt k_inv;
    if (!bigint_inv_mod(&k_inv, &k, &curve->n)) return 0;

    /* s = k^(-1) * (e + d*r) mod n */
    BigInt dr, sum_e_dr, s;
    bigint_mul_mod(&dr, &priv_d, &r, &curve->n);
    bigint_add_mod(&sum_e_dr, &hash_e, &dr, &curve->n);
    bigint_mul_mod(&s, &k_inv, &sum_e_dr, &curve->n);
    if (bigint_is_zero(&s)) return 0;

    sig->r = r;
    sig->s = s;
    return 1;
}

int ecdsa_sign(const ECCurve *curve, const BigInt priv_d, const BigInt hash_e, ECDSASignature *sig) {
    BigInt one, n_minus_1, k;
    bigint_set_u32(&one, 1);
    bigint_sub(&n_minus_1, &curve->n, &one);

    for (int attempts = 0; attempts < 1000; attempts++) {
        if (!bigint_random_range(&k, &one, &n_minus_1)) {
            return 0;
        }
        if (ecdsa_sign_with_k(curve, priv_d, hash_e, k, sig)) {
            return 1;
        }
    }
    return 0;
}

int ecdsa_verify(const ECCurve *curve, const ECPoint *pub_Q, const BigInt hash_e, const ECDSASignature *sig) {
    BigInt one, n_minus_1;
    bigint_set_u32(&one, 1);
    bigint_sub(&n_minus_1, &curve->n, &one);

    /* Paso 1: Comprobar r, s en [1, n - 1] */
    if (bigint_cmp(&sig->r, &one) < 0 || bigint_cmp(&sig->r, &n_minus_1) > 0) return 0;
    if (bigint_cmp(&sig->s, &one) < 0 || bigint_cmp(&sig->s, &n_minus_1) > 0) return 0;

    /* Validar que Q no sea infinito y pertenezca a la curva */
    if (pub_Q->is_infinity) return 0;
    if (!ecdsa_point_is_on_curve(curve, pub_Q)) return 0;

    /* Paso 3: w = s^(-1) mod n */
    BigInt w;
    if (!bigint_inv_mod(&w, &sig->s, &curve->n)) return 0;

    /* Paso 4: u1 = (e * w) mod n, u2 = (r * w) mod n */
    BigInt u1, u2;
    bigint_mul_mod(&u1, &hash_e, &w, &curve->n);
    bigint_mul_mod(&u2, &sig->r, &w, &curve->n);

    /* Paso 5: X = [u1]G + [u2]Q */
    ECPoint u1G, u2Q, X;
    ec_scalar_mul(curve, u1, &curve->G, &u1G);
    ec_scalar_mul(curve, u2, pub_Q, &u2Q);
    ec_point_add(curve, &u1G, &u2Q, &X);

    /* Paso 6: Si X = O, rechazar */
    if (X.is_infinity) return 0;

    /* Paso 7: v = x1 mod n */
    BigInt v;
    bigint_mod(&v, &X.x, &curve->n);

    /* Paso 8: Firma valida ssi v == r */
    return (bigint_cmp(&v, &sig->r) == 0);
}
