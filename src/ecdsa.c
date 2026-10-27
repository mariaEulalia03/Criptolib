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

    /*
     * Validacion canonica: las coordenadas deben pertenecer al campo F_p,
     * es decir 0 <= x,y < p. Sin este chequeo un punto con x o y >= p
     * pasaria la ecuacion tras la reduccion modular implicita, aceptando
     * claves publicas no canonicas.
     */
    if (bigint_cmp(&P->x, &curve->p) >= 0) return 0;
    if (bigint_cmp(&P->y, &curve->p) >= 0) return 0;

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

/*
 * Sobrescribe memoria sensible sin que el compilador pueda optimizarlo.
 */
static void secure_zero(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) {
        *p++ = 0;
    }
}

/*
 * Intercambio condicional de puntos sin ramas: con mask = 0xFFFFFFFF
 * intercambia p1 y p2; con mask = 0 no altera nada.
 */
static void ec_point_cswap(ECPoint *p1, ECPoint *p2, uint32_t mask) {
    for (int i = 0; i < BIGINT_WORDS; i++) {
        uint32_t t = (p1->x.limbs[i] ^ p2->x.limbs[i]) & mask;
        p1->x.limbs[i] ^= t;
        p2->x.limbs[i] ^= t;

        t = (p1->y.limbs[i] ^ p2->y.limbs[i]) & mask;
        p1->y.limbs[i] ^= t;
        p2->y.limbs[i] ^= t;
    }

    uint32_t t = ((uint32_t)p1->x.len ^ (uint32_t)p2->x.len) & mask;
    p1->x.len = (int)((uint32_t)p1->x.len ^ t);
    p2->x.len = (int)((uint32_t)p2->x.len ^ t);

    t = ((uint32_t)p1->y.len ^ (uint32_t)p2->y.len) & mask;
    p1->y.len = (int)((uint32_t)p1->y.len ^ t);
    p2->y.len = (int)((uint32_t)p2->y.len ^ t);

    t = ((uint32_t)p1->is_infinity ^ (uint32_t)p2->is_infinity) & mask;
    p1->is_infinity = (int)((uint32_t)p1->is_infinity ^ t);
    p2->is_infinity = (int)((uint32_t)p2->is_infinity ^ t);
}

void ec_scalar_mul(const ECCurve *curve, const BigInt k, const ECPoint *P, ECPoint *R) {
    if (bigint_is_zero(&k) || P->is_infinity) {
        R->is_infinity = 1;
        bigint_zero(&R->x);
        bigint_zero(&R->y);
        return;
    }

    /*
     * Escalera de Montgomery: en cada iteracion se ejecuta exactamente una
     * adicion y una duplicacion, sin ramas que dependan del bit de k.
     * Se recorren siempre 256 bits para no filtrar la longitud del escalar.
     */
    ECPoint r0, r1;
    r0.is_infinity = 1;
    bigint_zero(&r0.x);
    bigint_zero(&r0.y);
    r1 = *P;

    for (int i = 255; i >= 0; i--) {
        uint32_t mask = 0U - (uint32_t)bigint_get_bit(&k, i);

        ec_point_cswap(&r0, &r1, mask);
        ec_point_add(curve, &r0, &r1, &r1); /* r1 = r0 + r1 */
        ec_point_double(curve, &r0, &r0);   /* r0 = 2 * r0 */
        ec_point_cswap(&r0, &r1, mask);
    }

    *R = r0;
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

    /* k^(-1) mod n: k es secreto, se usa la exponenciacion en escalera */
    BigInt k_inv;
    if (!bigint_inv_mod_fermat(&k_inv, &k, &curve->n)) return 0;

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

/*
 * Generacion determinista de k segun RFC 6979 (seccion 3.2), con
 * HMAC-SHA256 e int2octets/bits2octets sobre el orden n de la curva.
 * Elimina la dependencia del CSPRNG en la firma: mismo (d, mensaje)
 * produce siempre la misma (r, s).
 */
int ecdsa_sign(const ECCurve *curve, const BigInt priv_d, const BigInt hash_e, ECDSASignature *sig) {
    uint8_t V[32];
    uint8_t K[32];
    uint8_t buf[97]; /* V || 0x00/0x01 || d_octets || h_octets */
    uint8_t d_bytes[32];
    uint8_t h_octets[32];

    BigInt h_mod, k_candidate, one, n_minus_1;
    int ok = 0;

    /*
     * RFC 6979 §2.3.2: bits2octets(H(m)) = int2octets(bits2int(H(m)) mod n).
     * Con SHA-256 y P-256 ambos son de 256 bits, por lo que basta reducir mod n.
     */
    bigint_mod(&h_mod, &hash_e, &curve->n);
    bigint_to_bytes(&priv_d, d_bytes, sizeof(d_bytes));
    bigint_to_bytes(&h_mod, h_octets, sizeof(h_octets));

    /* Paso a y b: V = 0x01..., K = 0x00... */
    memset(V, 0x01, sizeof(V));
    memset(K, 0x00, sizeof(K));

    /* Paso c: K = HMAC_K(V || 0x00 || int2octets(d) || bits2octets(h)) */
    memcpy(buf, V, 32);
    buf[32] = 0x00;
    memcpy(buf + 33, d_bytes, 32);
    memcpy(buf + 65, h_octets, 32);
    hmac_sha256(K, sizeof(K), buf, sizeof(buf), K);

    /* Paso d: V = HMAC_K(V) */
    hmac_sha256(K, sizeof(K), V, sizeof(V), V);

    /* Paso e: K = HMAC_K(V || 0x01 || int2octets(d) || bits2octets(h)) */
    memcpy(buf, V, 32);
    buf[32] = 0x01;
    memcpy(buf + 33, d_bytes, 32);
    memcpy(buf + 65, h_octets, 32);
    hmac_sha256(K, sizeof(K), buf, sizeof(buf), K);

    /* Paso f: V = HMAC_K(V) */
    hmac_sha256(K, sizeof(K), V, sizeof(V), V);

    bigint_set_u32(&one, 1);
    bigint_sub(&n_minus_1, &curve->n, &one);

    /* Paso h: candidatos k = bits2int(V) mientras no se obtenga firma valida */
    for (int attempts = 0; attempts < 100 && !ok; attempts++) {
        hmac_sha256(K, sizeof(K), V, sizeof(V), V);
        bigint_from_bytes(&k_candidate, V, sizeof(V));

        if (bigint_cmp(&k_candidate, &one) >= 0 &&
            bigint_cmp(&k_candidate, &n_minus_1) <= 0) {
            if (ecdsa_sign_with_k(curve, priv_d, hash_e, k_candidate, sig)) {
                ok = 1;
            }
        }

        if (!ok) {
            /* K = HMAC_K(V || 0x00); V = HMAC_K(V) */
            memcpy(buf, V, 32);
            buf[32] = 0x00;
            hmac_sha256(K, sizeof(K), buf, 33, K);
            hmac_sha256(K, sizeof(K), V, sizeof(V), V);
        }
    }

    secure_zero(V, sizeof(V));
    secure_zero(K, sizeof(K));
    secure_zero(buf, sizeof(buf));
    secure_zero(d_bytes, sizeof(d_bytes));
    secure_zero(h_octets, sizeof(h_octets));
    secure_zero(&k_candidate, sizeof(k_candidate));

    return ok;
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
