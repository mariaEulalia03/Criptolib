#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "ecdsa.h"

#define COLOR_RESET  "\033[0m"
#define COLOR_GREEN  "\033[32m"
#define COLOR_RED    "\033[31m"
#define COLOR_CYAN   "\033[36m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_BOLD   "\033[1m"

static int g_tests_passed = 0;
static int g_tests_failed = 0;

static void assert_condition(int condition, const char *test_name) {
    if (condition) {
        printf("  [%sPASS%s] %s\n", COLOR_GREEN, COLOR_RESET, test_name);
        g_tests_passed++;
    } else {
        printf("  [%sFAIL%s] %s\n", COLOR_RED, COLOR_RESET, test_name);
        g_tests_failed++;
    }
}

static void print_hex_label(const char *label, const BigInt *val) {
    char hex[256];
    bigint_to_hex(val, hex, sizeof(hex));
    printf("    %s: 0x%s\n", label, hex);
}

/* Conversion de bytes a cadena hexadecimal mayuscula (con ceros a la izquierda) */
static void bytes_to_hex(const uint8_t *bytes, size_t len, char *out) {
    static const char *digits = "0123456789ABCDEF";
    for (size_t i = 0; i < len; i++) {
        out[i * 2]     = digits[(bytes[i] >> 4) & 0xF];
        out[i * 2 + 1] = digits[bytes[i] & 0xF];
    }
    out[len * 2] = '\0';
}

/* ========================================================================= */
/*                    FASE 0: PRUEBAS UNITARIAS DE SHA-256                   */
/* ========================================================================= */

static void test_sha256_kat(void) {
    printf("\n%s=== FASE 0: Vectores de Prueba SHA-256 (FIPS 180-4) ===%s\n", COLOR_CYAN, COLOR_RESET);

    struct {
        const char *msg;
        const char *expected;
    } vectors[] = {
        {"", "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"},
        {"abc", "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"},
        {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         "248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1"},
        {"The quick brown fox jumps over the lazy dog",
         "D7A8FBB307D7809469CA9ABCB0082E4F8D5651E46D3CDB762D02D0BF37C9E592"},
    };

    size_t n_vectors = sizeof(vectors) / sizeof(vectors[0]);
    for (size_t i = 0; i < n_vectors; i++) {
        uint8_t hash[32];
        char hex[65];
        char name[160];

        sha256_hash((const uint8_t *)vectors[i].msg, strlen(vectors[i].msg), hash);
        bytes_to_hex(hash, sizeof(hash), hex);

        snprintf(name, sizeof(name), "SHA-256 KAT: \"%s\"",
                 (vectors[i].msg[0] != '\0') ? vectors[i].msg : "(cadena vacia)");
        assert_condition(strcmp(hex, vectors[i].expected) == 0, name);
    }

    /* El procesamiento incremental en varios bloques debe dar el mismo digest */
    const char *msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    uint8_t one_shot[32], incremental[32];
    char hex_one_shot[65], hex_incremental[65];
    sha256_ctx ctx;

    sha256_hash((const uint8_t *)msg, strlen(msg), one_shot);
    sha256_init(&ctx);
    sha256_update(&ctx, (const uint8_t *)msg, 7);
    sha256_update(&ctx, (const uint8_t *)msg + 7, strlen(msg) - 7);
    sha256_final(&ctx, incremental);

    bytes_to_hex(one_shot, sizeof(one_shot), hex_one_shot);
    bytes_to_hex(incremental, sizeof(incremental), hex_incremental);
    assert_condition(strcmp(hex_one_shot, hex_incremental) == 0,
                     "SHA-256: procesamiento incremental coincide con sha256_hash");
}

/* ========================================================================= */
/*                  FASE 0: HMAC-SHA256 (Vectores RFC 4231)                  */
/* ========================================================================= */

static void test_hmac_sha256_rfc4231(void) {
    printf("\n%s=== FASE 0: HMAC-SHA256 (RFC 4231) ===%s\n", COLOR_CYAN, COLOR_RESET);

    uint8_t key1[20];
    uint8_t key6[131];
    uint8_t mac[32];
    char hex[65];

    /* Caso 1: clave de 20 bytes 0x0b */
    memset(key1, 0x0b, sizeof(key1));
    const char *data1 = "Hi There";
    hmac_sha256(key1, sizeof(key1), (const uint8_t *)data1, strlen(data1), mac);
    bytes_to_hex(mac, sizeof(mac), hex);
    assert_condition(strcmp(hex, "B0344C61D8DB38535CA8AFCEAF0BF12B881DC200C9833DA726E9376C2E32CFF7") == 0,
                     "HMAC-SHA256 KAT 1 (RFC 4231): clave 0x0b x 20");

    /* Caso 2: clave de 4 bytes "Jefe" */
    const char *data2 = "what do ya want for nothing?";
    hmac_sha256((const uint8_t *)"Jefe", 4, (const uint8_t *)data2, strlen(data2), mac);
    bytes_to_hex(mac, sizeof(mac), hex);
    assert_condition(strcmp(hex, "5BDCC146BF60754E6A042426089575C75A003F089D2739839DEC58B964EC3843") == 0,
                     "HMAC-SHA256 KAT 2 (RFC 4231): clave corta \"Jefe\"");

    /* Caso 6: clave de 131 bytes (> bloque) para ejercitar el hash de la clave */
    memset(key6, 0xaa, sizeof(key6));
    const char *data6 = "Test Using Larger Than Block-Size Key - Hash Key First";
    hmac_sha256(key6, sizeof(key6), (const uint8_t *)data6, strlen(data6), mac);
    bytes_to_hex(mac, sizeof(mac), hex);
    assert_condition(strcmp(hex, "60E431591EE0B67F0D8A26AACBF5B77F8E0BC6213728C5140546040F0EE37F54") == 0,
                     "HMAC-SHA256 KAT 6 (RFC 4231): clave mayor a 64 bytes");
}

/* ========================================================================= */
/*                    FASE 0: PRUEBAS UNITARIAS DE BigInt                    */
/* ========================================================================= */

static void test_bigint_unit(const ECCurve *curve) {
    printf("\n%s=== FASE 0: Pruebas Unitarias de Aritmetica BigInt ===%s\n", COLOR_CYAN, COLOR_RESET);

    BigInt a, b, res, q, rem, check, prod;
    char hex[256];

    /* Suma con acarreo entre palabras */
    bigint_from_hex(&a, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
    bigint_from_hex(&b, "1");
    bigint_add(&res, &a, &b);
    bigint_to_hex(&res, hex, sizeof(hex));
    assert_condition(strcmp(hex, "100000000000000000000000000000000") == 0,
                     "BigInt: suma propaga el acarreo entre palabras");

    /* Resta que revierte la suma */
    bigint_sub(&res, &res, &b);
    bigint_to_hex(&res, hex, sizeof(hex));
    assert_condition(strcmp(hex, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF") == 0,
                     "BigInt: resta recupera el valor original");

    /* Resta con resultado negativo debe rechazarse */
    assert_condition(bigint_sub(&res, &b, &a) == -1,
                     "BigInt: resta con minuendo menor es rechazada (a >= b)");

    /* Multiplicacion 64 x 64 -> 128 bits */
    bigint_from_hex(&a, "FFFFFFFFFFFFFFFF");
    bigint_mul(&res, &a, &a);
    bigint_to_hex(&res, hex, sizeof(hex));
    assert_condition(strcmp(hex, "FFFFFFFFFFFFFFFE0000000000000001") == 0,
                     "BigInt: multiplicacion de 64 x 64 bits es exacta");

    /* Division: a = q * b + r con 0 <= r < b */
    bigint_from_hex(&a, "123456789ABCDEF0123456789ABCDEF0");
    bigint_from_hex(&b, "100000000");
    bigint_div(&q, &rem, &a, &b);
    bigint_mul(&prod, &q, &b);
    bigint_add(&check, &prod, &rem);
    assert_condition(bigint_cmp(&check, &a) == 0 && bigint_cmp(&rem, &b) < 0,
                     "BigInt: division cumple a = q*b + r con r < b");

    /* Modulo coincide con el resto de la division */
    bigint_mod(&res, &a, &b);
    assert_condition(bigint_cmp(&res, &rem) == 0,
                     "BigInt: modulo coincide con el resto de la division");

    /* Inverso modular existente: 7^-1 mod 13 = 2 */
    bigint_set_u32(&a, 7);
    bigint_set_u32(&b, 13);
    int inv_ok = bigint_inv_mod(&res, &a, &b);
    bigint_to_hex(&res, hex, sizeof(hex));
    assert_condition(inv_ok && strcmp(hex, "2") == 0,
                     "BigInt: inverso modular 7^-1 mod 13 = 2");

    /* Inverso modular inexistente: 2 no es invertible mod 4 (modulo par) */
    bigint_set_u32(&a, 2);
    bigint_set_u32(&b, 4);
    assert_condition(bigint_inv_mod(&res, &a, &b) == 0 && bigint_is_zero(&res),
                     "BigInt: inverso modular inexistente devuelve error (modulo par)");

    /* Inverso modular inexistente con modulo impar: 3 no es invertible mod 9 */
    bigint_set_u32(&a, 3);
    bigint_set_u32(&b, 9);
    assert_condition(bigint_inv_mod(&res, &a, &b) == 0 && bigint_is_zero(&res),
                     "BigInt: inverso modular inexistente devuelve error (mcd > 1)");

    /* Exponenciacion modular por escalera: 2^10 mod 1000 = 24 y 3^7 mod 13 = 3 */
    BigInt mod1000;
    bigint_set_u32(&mod1000, 1000);
    bigint_set_u32(&a, 2);
    bigint_set_u32(&b, 10);
    bigint_exp_mod(&res, &a, &b, &mod1000);
    bigint_to_hex(&res, hex, sizeof(hex));
    int exp_ok_1 = (strcmp(hex, "18") == 0);

    bigint_set_u32(&a, 3);
    bigint_set_u32(&b, 7);
    bigint_set_u32(&mod1000, 13);
    bigint_exp_mod(&res, &a, &b, &mod1000);
    bigint_to_hex(&res, hex, sizeof(hex));
    int exp_ok_2 = (strcmp(hex, "3") == 0);
    assert_condition(exp_ok_1 && exp_ok_2,
                     "BigInt: exponenciacion modular 2^10 mod 1000 y 3^7 mod 13");

    /* Inverso por Pequeno Teorema de Fermat: 7^-1 mod 13 = 2 */
    bigint_set_u32(&a, 7);
    bigint_set_u32(&b, 13);
    int fermat_ok = bigint_inv_mod_fermat(&res, &a, &b);
    bigint_to_hex(&res, hex, sizeof(hex));
    assert_condition(fermat_ok && strcmp(hex, "2") == 0,
                     "BigInt: inverso por Fermat 7^-1 mod 13 = 2");

    /* Fermat debe rechazar entradas no invertibles */
    bigint_set_u32(&a, 3);
    bigint_set_u32(&b, 9);
    assert_condition(bigint_inv_mod_fermat(&res, &a, &b) == 0 && bigint_is_zero(&res),
                     "BigInt: inverso por Fermat rechaza 3 mod 9");

    bigint_set_u32(&a, 2);
    bigint_set_u32(&b, 4);
    assert_condition(bigint_inv_mod_fermat(&res, &a, &b) == 0 && bigint_is_zero(&res),
                     "BigInt: inverso por Fermat rechaza 2 mod 4");

    /* Desplazamientos ida y vuelta */
    bigint_set_u32(&a, 1);
    bigint_shift_left(&a, &a, 130);
    bigint_shift_right(&a, &a, 130);
    bigint_to_hex(&a, hex, sizeof(hex));
    assert_condition(strcmp(hex, "1") == 0,
                     "BigInt: desplazamientos izquierda/derecha son reversibles");

    /* Conversion bytes <-> BigInt reversible */
    uint8_t bytes_in[32], bytes_out[32];
    for (int i = 0; i < 32; i++) bytes_in[i] = (uint8_t)(0xA0 + i);
    bigint_from_bytes(&a, bytes_in, sizeof(bytes_in));
    bigint_to_bytes(&a, bytes_out, sizeof(bytes_out));
    assert_condition(memcmp(bytes_in, bytes_out, sizeof(bytes_in)) == 0,
                     "BigInt: conversion bytes <-> BigInt es reversible");

    /* Parseo hexadecimal: prefijo 0x y mayusculas/minusculas */
    int parsed_0x = bigint_from_hex(&a, "0xDeadBeef");
    bigint_to_hex(&a, hex, sizeof(hex));
    assert_condition(parsed_0x == 0 && strcmp(hex, "DEADBEEF") == 0,
                     "BigInt: parseo hexadecimal con prefijo 0x");

    /* Entradas invalidas: caracter no hexadecimal, cadena vacia y desbordamiento */
    assert_condition(bigint_from_hex(&a, "12ZZ") == -1 && bigint_is_zero(&a),
                     "BigInt: hex con caracter invalido es rechazado");
    assert_condition(bigint_from_hex(&a, "") == -1 && bigint_is_zero(&a),
                     "BigInt: cadena hexadecimal vacia es rechazada");

    char big_hex[163];
    big_hex[0] = '1';
    memset(big_hex + 1, '0', 160);
    big_hex[161] = '\0'; /* 161 digitos = 644 bits > capacidad */
    assert_condition(bigint_from_hex(&a, big_hex) == -1 && bigint_is_zero(&a),
                     "BigInt: hex de mas de 640 bits es rechazado (sin truncamiento)");

    memset(big_hex, 'F', 160);
    big_hex[160] = '\0'; /* 160 digitos = 640 bits exactos */
    assert_condition(bigint_from_hex(&a, big_hex) == 0 && bigint_bit_length(&a) == 640,
                     "BigInt: hex de 160 digitos (640 bits) es aceptado");

    /* Muestreo aleatorio acotado al rango [1, n-1] */
    BigInt one, n_minus_1, rnd;
    bigint_set_u32(&one, 1);
    bigint_sub(&n_minus_1, &curve->n, &one);

    int in_range = 1;
    for (int i = 0; i < 16; i++) {
        if (!bigint_random_range(&rnd, &one, &n_minus_1) ||
            bigint_cmp(&rnd, &one) < 0 || bigint_cmp(&rnd, &n_minus_1) > 0) {
            in_range = 0;
            break;
        }
    }
    assert_condition(in_range, "BigInt: muestreo aleatorio en [1, n-1] respeta el rango");

    assert_condition(bigint_random_range(&rnd, &one, &one) && bigint_is_one(&rnd),
                     "BigInt: rango degenerado [1, 1] devuelve el limite");
}

/* ========================================================================= */
/*                          FASE 1 Y 2: CONTROL DE CURVA                     */
/* ========================================================================= */

void test_fase1_y_2_arimetica(const ECCurve *curve) {
    printf("\n%s=== FASE 1 Y 2: Inicializacion y Aritmetica de Puntos P-256 ===%s\n", COLOR_CYAN, COLOR_RESET);

    /* 1. Verificar que el punto base G pertenece a la curva */
    int g_on_curve = ecdsa_point_is_on_curve(curve, &curve->G);
    assert_condition(g_on_curve, "Punto generador base G pertenece a Curve P-256");

    /* 2. Verificar que [1]G == G */
    BigInt one;
    bigint_set_u32(&one, 1);
    ECPoint oneG;
    ec_scalar_mul(curve, one, &curve->G, &oneG);
    int is_1g_correct = (!oneG.is_infinity &&
                         bigint_cmp(&oneG.x, &curve->G.x) == 0 &&
                         bigint_cmp(&oneG.y, &curve->G.y) == 0);
    assert_condition(is_1g_correct, "Multiplicacion escalar [1]G coincide exactamente con G");

    /* 3. Verificar que 2G calculado con ec_point_double coincide con vector oficial */
    ECPoint twoG;
    ec_point_double(curve, &curve->G, &twoG);

    BigInt expected_2Gx, expected_2Gy;
    bigint_from_hex(&expected_2Gx, "7CF27B188D034F7E8A52380304B51AC3C08969E277F21B35A60B48FC47669978");
    bigint_from_hex(&expected_2Gy, "7775510DB8ED040293D9AC69F7430DBBA7DADE63CE982299E04B79D227873D1");

    int is_2g_correct = (!twoG.is_infinity &&
                         bigint_cmp(&twoG.x, &expected_2Gx) == 0 &&
                         bigint_cmp(&twoG.y, &expected_2Gy) == 0);
    assert_condition(is_2g_correct, "Duplicacion de punto ec_point_double(G) coincide bit a bit con 2G oficial");

    /* 4. Verificar que [2]G con scalar_mul coincide con ec_point_double */
    BigInt two;
    bigint_set_u32(&two, 2);
    ECPoint twoG_scalar;
    ec_scalar_mul(curve, two, &curve->G, &twoG_scalar);
    int is_scalar_double_equiv = (bigint_cmp(&twoG.x, &twoG_scalar.x) == 0 &&
                                  bigint_cmp(&twoG.y, &twoG_scalar.y) == 0);
    assert_condition(is_scalar_double_equiv, "Equivalencia entre ec_point_double(G) y ec_scalar_mul(2, G)");

    /* 5. Verificar que [n]G == O (Punto en el infinito) */
    ECPoint nG;
    ec_scalar_mul(curve, curve->n, &curve->G, &nG);
    assert_condition(nG.is_infinity, "Orden primo [n]G resulta en el punto en el infinito (O)");
}

/* ========================================================================= */
/*                          FASE 3: VECTORES NIST CAVP                       */
/* ========================================================================= */

void test_fase3_vectores_cavp(const ECCurve *curve) {
    printf("\n%s=== FASE 3: Validacion con Vectores Oficiales del NIST CAVP ===%s\n", COLOR_CYAN, COLOR_RESET);

    /*
     * Vector Oficial NIST CAVP (FIPS 186-4/5 ECDSA P-256 SHA-256)
     */
    const char *cavp_d_hex = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721";
    const char *cavp_k_hex = "A6FE30047443EE12746441364D3E5B191435A942F84369992999F3565FB05A1F";
    const char *cavp_e_hex = "1AAB2E8797DBEFE22B675EB3FB917A85380C0DBE2EAF834E6D06058467BE7786";
    const char *cavp_expected_r = "614B38169454720149B2C66C185AAB68563CDB9C2220A858ED8318A354AFCAD4";
    const char *cavp_expected_s = "36AE7E05B4016D5DF650C22F3CE0D3EB84111A6021B5C79FEC56C2E64CA8FFEF";

    BigInt d, k, e, exp_r, exp_s;
    bigint_from_hex(&d, cavp_d_hex);
    bigint_from_hex(&k, cavp_k_hex);
    bigint_from_hex(&e, cavp_e_hex);
    bigint_from_hex(&exp_r, cavp_expected_r);
    bigint_from_hex(&exp_s, cavp_expected_s);

    /* 1. Generacion de Clave Publica Q = [d]G */
    ECPoint pub_Q;
    int keygen_ok = ecdsa_keygen(curve, d, &pub_Q);
    assert_condition(keygen_ok, "Generacion y validacion de clave publica NIST CAVP Q = [d]G");

    /* 2. Firma determinista con k fijo */
    ECDSASignature sig;
    int sign_ok = ecdsa_sign_with_k(curve, d, e, k, &sig);
    assert_condition(sign_ok, "Generacion de firma con k fijo (NIST CAVP)");

    int r_match = (bigint_cmp(&sig.r, &exp_r) == 0);
    int s_match = (bigint_cmp(&sig.s, &exp_s) == 0);
    assert_condition(r_match, "Componente de firma 'r' coincide bit a bit con CAVP");
    assert_condition(s_match, "Componente de firma 's' coincide bit a bit con CAVP");

    /* 3. Verificacion de la firma oficial */
    int verify_ok = ecdsa_verify(curve, &pub_Q, e, &sig);
    assert_condition(verify_ok, "Verificacion ecdsa_verify exitosa con vector CAVP (v == r)");
}

/* ========================================================================= */
/*              FASE 3B: FIRMA DETERMINISTA RFC 6979 (P-256/SHA-256)         */
/* ========================================================================= */

static void test_rfc6979(const ECCurve *curve) {
    printf("\n%s=== FASE 3B: Firma determinista RFC 6979 (P-256 / SHA-256) ===%s\n", COLOR_CYAN, COLOR_RESET);

    /* Clave privada del Apendice A.2.5 de RFC 6979 */
    BigInt d;
    bigint_from_hex(&d, "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");

    ECPoint pub_Q;
    ecdsa_keygen(curve, d, &pub_Q);

    struct {
        const char *msg;
        const char *r;
        const char *s;
    } vectors[] = {
        {"sample",
         "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716",
         "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8"},
        {"test",
         "F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367",
         "019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083"},
    };

    size_t n_vectors = sizeof(vectors) / sizeof(vectors[0]);
    for (size_t i = 0; i < n_vectors; i++) {
        uint8_t hash_bytes[32];
        BigInt e, expected_r, expected_s;
        ECDSASignature sig;
        char name[160];

        sha256_hash((const uint8_t *)vectors[i].msg, strlen(vectors[i].msg), hash_bytes);
        sha256_to_bigint(hash_bytes, &e);
        bigint_from_hex(&expected_r, vectors[i].r);
        bigint_from_hex(&expected_s, vectors[i].s);

        int ok = ecdsa_sign(curve, d, e, &sig);

        /* Se comparan como BigInt: bigint_to_hex no conserva ceros a la izquierda */
        snprintf(name, sizeof(name),
                 "RFC 6979: (r, s) deterministas coinciden con el vector \"%s\"", vectors[i].msg);
        assert_condition(ok &&
                         bigint_cmp(&sig.r, &expected_r) == 0 &&
                         bigint_cmp(&sig.s, &expected_s) == 0,
                         name);
        assert_condition(ecdsa_verify(curve, &pub_Q, e, &sig),
                         "RFC 6979: firma determinista verificada con ecdsa_verify");
    }

    /* La misma entrada debe producir exactamente la misma firma (determinismo) */
    uint8_t hash_bytes[32];
    sha256_hash((const uint8_t *)"sample", 6, hash_bytes);
    BigInt e;
    sha256_to_bigint(hash_bytes, &e);

    ECDSASignature sig_a, sig_b;
    ecdsa_sign(curve, d, e, &sig_a);
    ecdsa_sign(curve, d, e, &sig_b);
    assert_condition(bigint_cmp(&sig_a.r, &sig_b.r) == 0 && bigint_cmp(&sig_a.s, &sig_b.s) == 0,
                     "RFC 6979: dos firmas del mismo mensaje son identicas");
}

/* ========================================================================= */
/*                          FASE 4: INTEGRACION Y CASOS DE PRUEBA REALES     */
/* ========================================================================= */

void test_fase4_flujo_completo(const ECCurve *curve) {
    printf("\n%s=== FASE 4: Flujo Completo con Mensaje Real y Pruebas de Seguridad ===%s\n", COLOR_CYAN, COLOR_RESET);

    /* 1. Generacion de Par de Claves Real */
    BigInt priv_d;
    ECPoint pub_Q;
    int kg_ok = ecdsa_generate_keypair(curve, &priv_d, &pub_Q);
    assert_condition(kg_ok, "Generacion de nuevo par de claves aleatorias (d, Q) mediante CSPRNG");

    print_hex_label("Clave Privada (d)", &priv_d);
    print_hex_label("Clave Publica (Q.x)", &pub_Q.x);
    print_hex_label("Clave Publica (Q.y)", &pub_Q.y);

    /* 2. Hash SHA-256 de un Mensaje Real */
    const char *mensaje_original = "Universidad de Cuenca - Seguridad Informatica - ECDSA CryptoLib 2026";
    printf("    Mensaje a firmar: \"%s\"\n", mensaje_original);

    uint8_t hash_bytes[32];
    sha256_hash((const uint8_t *)mensaje_original, strlen(mensaje_original), hash_bytes);

    BigInt hash_e;
    sha256_to_bigint(hash_bytes, &hash_e);
    print_hex_label("Hash SHA-256 (e)", &hash_e);

    /* 3. Firma del mensaje con ecdsa_sign */
    ECDSASignature firma;
    int sign_ok = ecdsa_sign(curve, priv_d, hash_e, &firma);
    assert_condition(sign_ok, "Firma digital del mensaje original generada exitosamente");
    print_hex_label("Firma r", &firma.r);
    print_hex_label("Firma s", &firma.s);

    /* 4. Verificacion de la firma valida */
    int verify_valid = ecdsa_verify(curve, &pub_Q, hash_e, &firma);
    assert_condition(verify_valid, "Verificacion de autenticidad e integridad del mensaje (Aceptada)");

    /* 5. Deteccion de alteraciones en el mensaje (Ataque de Tampering) */
    const char *mensaje_alterado = "Universidad de Cuenca - Seguridad Informatica - ECDSA CryptoLib 2027";
    uint8_t hash_alterado_bytes[32];
    sha256_hash((const uint8_t *)mensaje_alterado, strlen(mensaje_alterado), hash_alterado_bytes);
    BigInt hash_alterado_e;
    sha256_to_bigint(hash_alterado_bytes, &hash_alterado_e);

    int verify_tampered = ecdsa_verify(curve, &pub_Q, hash_alterado_e, &firma);
    assert_condition(!verify_tampered, "Deteccion de manipulacion: mensaje alterado fue RECHAZADO");

    /* 6. Deteccion de firma con clave publica equivocada (Wrong Key Attack) */
    BigInt wrong_d;
    ECPoint wrong_pub_Q;
    ecdsa_generate_keypair(curve, &wrong_d, &wrong_pub_Q);
    int verify_wrong_key = ecdsa_verify(curve, &wrong_pub_Q, hash_e, &firma);
    assert_condition(!verify_wrong_key, "Proteccion de identidad: firma verificada con clave ajena fue RECHAZADA");

    /* 7. Deteccion de corrupcion en componentes de la firma (Corrupted Signature) */
    ECDSASignature firma_corrupta = firma;
    BigInt one;
    bigint_set_u32(&one, 1);
    bigint_add(&firma_corrupta.s, &firma_corrupta.s, &one); /* s corrupto */
    int verify_corrupted = ecdsa_verify(curve, &pub_Q, hash_e, &firma_corrupta);
    assert_condition(!verify_corrupted, "Deteccion de firma adulterada (s modificado) fue RECHAZADA");
}

/* ========================================================================= */
/*          FASE 5: VALIDACION CANONICA Y CASOS BORDE DE LA API              */
/* ========================================================================= */

void test_validaciones_borde(const ECCurve *curve) {
    printf("\n%s=== FASE 5: Validacion Canonica y Casos Borde ===%s\n", COLOR_CYAN, COLOR_RESET);

    /* Firma valida de referencia */
    BigInt priv_d;
    ECPoint pub_Q;
    ecdsa_generate_keypair(curve, &priv_d, &pub_Q);

    const char *mensaje = "Validacion canonica de clave publica";
    uint8_t hash_bytes[32];
    sha256_hash((const uint8_t *)mensaje, strlen(mensaje), hash_bytes);

    BigInt hash_e;
    sha256_to_bigint(hash_bytes, &hash_e);

    ECDSASignature firma;
    ecdsa_sign(curve, priv_d, hash_e, &firma);

    /* 1. Coordenada x no canonica: x' = x + p (se reduce a x mod p) */
    ECPoint no_canonico_x = pub_Q;
    bigint_add(&no_canonico_x.x, &pub_Q.x, &curve->p);
    assert_condition(!ecdsa_point_is_on_curve(curve, &no_canonico_x),
                     "Punto con x >= p es rechazado por la validacion canonica");
    assert_condition(!ecdsa_verify(curve, &no_canonico_x, hash_e, &firma),
                     "ecdsa_verify rechaza una clave publica no canonica (x + p)");

    /* 2. Coordenada y no canonica: y' = y + p */
    ECPoint no_canonico_y = pub_Q;
    bigint_add(&no_canonico_y.y, &pub_Q.y, &curve->p);
    assert_condition(!ecdsa_verify(curve, &no_canonico_y, hash_e, &firma),
                     "ecdsa_verify rechaza una clave publica no canonica (y + p)");

    /* 3. Componentes r y s fuera de [1, n-1] */
    ECDSASignature sig_invalida = firma;
    bigint_zero(&sig_invalida.r);
    assert_condition(!ecdsa_verify(curve, &pub_Q, hash_e, &sig_invalida),
                     "ecdsa_verify rechaza r = 0");

    sig_invalida = firma;
    bigint_zero(&sig_invalida.s);
    assert_condition(!ecdsa_verify(curve, &pub_Q, hash_e, &sig_invalida),
                     "ecdsa_verify rechaza s = 0");

    sig_invalida = firma;
    bigint_add(&sig_invalida.s, &firma.s, &curve->n); /* s' = s + n >= n */
    assert_condition(!ecdsa_verify(curve, &pub_Q, hash_e, &sig_invalida),
                     "ecdsa_verify rechaza s fuera del rango [1, n-1]");

    /* 4. Claves privadas invalidas en keygen */
    BigInt d_invalida;
    ECPoint Q_tmp;
    Q_tmp.is_infinity = 1;

    bigint_zero(&d_invalida);
    assert_condition(!ecdsa_keygen(curve, d_invalida, &Q_tmp),
                     "ecdsa_keygen rechaza d = 0");

    bigint_copy(&d_invalida, &curve->n);
    assert_condition(!ecdsa_keygen(curve, d_invalida, &Q_tmp),
                     "ecdsa_keygen rechaza d = n");

    /* 5. Clave publica en el infinito */
    ECPoint infinito;
    infinito.is_infinity = 1;
    bigint_zero(&infinito.x);
    bigint_zero(&infinito.y);
    assert_condition(!ecdsa_verify(curve, &infinito, hash_e, &firma),
                     "ecdsa_verify rechaza la clave publica en el infinito");
}

int main(void) {
    printf("%s=================================================================%s\n", COLOR_BOLD, COLOR_RESET);
    printf("%s   CRYPTOLIB: BANCO DE PRUEBAS DE VALIDACION DEL ESTANDAR ECDSA  %s\n", COLOR_BOLD, COLOR_RESET);
    printf("%s   NIST FIPS PUB 186-5 / NIST SP 800-186 / CURVE P-256 (SECP256R1) %s\n", COLOR_BOLD, COLOR_RESET);
    printf("%s=================================================================%s\n", COLOR_BOLD, COLOR_RESET);

    ECCurve curve;
    ec_init_p256(&curve);

    test_sha256_kat();
    test_hmac_sha256_rfc4231();
    test_bigint_unit(&curve);
    test_fase1_y_2_arimetica(&curve);
    test_fase3_vectores_cavp(&curve);
    test_rfc6979(&curve);
    test_fase4_flujo_completo(&curve);
    test_validaciones_borde(&curve);

    printf("\n%s-----------------------------------------------------------------%s\n", COLOR_BOLD, COLOR_RESET);
    printf("RESUMEN DE PRUEBAS:\n");
    printf("  Superadas: %s%d%s\n", COLOR_GREEN, g_tests_passed, COLOR_RESET);
    printf("  Fallidas:  %s%d%s\n", (g_tests_failed > 0 ? COLOR_RED : COLOR_GREEN), g_tests_failed, COLOR_RESET);
    printf("%s-----------------------------------------------------------------%s\n", COLOR_BOLD, COLOR_RESET);

    return (g_tests_failed == 0) ? 0 : 1;
}
