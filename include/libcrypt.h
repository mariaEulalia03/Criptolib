#ifndef CRYPTOLIB_LIBCRYPT_H
#define CRYPTOLIB_LIBCRYPT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================= */
/*                          ARITMETICA BIGINT                                */
/* ========================================================================= */

#define BIGINT_WORDS 20  /* 20 palabras de 32 bits = 640 bits (suficiente para P-256 y productos intermedios) */

typedef struct {
    uint32_t limbs[BIGINT_WORDS]; /* Extremidad menos significativa en limbs[0] */
    int len;                      /* Cantidad de palabras activas */
} BigInt;

/* Inicializacion y asignacion */
void bigint_init(BigInt *a);
void bigint_zero(BigInt *a);
void bigint_set_u32(BigInt *a, uint32_t val);
void bigint_set_u64(BigInt *a, uint64_t val);
void bigint_copy(BigInt *dst, const BigInt *src);

/* Conversion Hexadecimal y Bytes */
int  bigint_from_hex(BigInt *a, const char *hex_str);
void bigint_to_hex(const BigInt *a, char *out_buf, size_t max_len);
int  bigint_from_bytes(BigInt *a, const uint8_t *bytes, size_t len);
void bigint_to_bytes(const BigInt *a, uint8_t *bytes, size_t len);

/* Comparaciones e Inspeccion */
int bigint_cmp(const BigInt *a, const BigInt *b);
int bigint_is_zero(const BigInt *a);
int bigint_is_one(const BigInt *a);
int bigint_is_even(const BigInt *a);
int bigint_bit_length(const BigInt *a);
int bigint_get_bit(const BigInt *a, int bit_idx);
void bigint_set_bit(BigInt *a, int bit_idx, int val);

/* Desplazamientos */
void bigint_shift_left(BigInt *res, const BigInt *a, int bits);
void bigint_shift_right(BigInt *res, const BigInt *a, int bits);

/* Operaciones Basicas */
int  bigint_add(BigInt *res, const BigInt *a, const BigInt *b);
int  bigint_sub(BigInt *res, const BigInt *a, const BigInt *b); /* Requiere a >= b */
void bigint_mul(BigInt *res, const BigInt *a, const BigInt *b);
void bigint_div(BigInt *q, BigInt *r, const BigInt *a, const BigInt *b);

/* Aritmetica Modular */
void bigint_mod(BigInt *res, const BigInt *a, const BigInt *m);
void bigint_add_mod(BigInt *res, const BigInt *a, const BigInt *b, const BigInt *m);
void bigint_sub_mod(BigInt *res, const BigInt *a, const BigInt *b, const BigInt *m);
void bigint_mul_mod(BigInt *res, const BigInt *a, const BigInt *b, const BigInt *m);
/* Inverso modular NIST B.2 (requiere modulo impar y mcd(k, m) == 1) */
int  bigint_inv_mod(BigInt *res, const BigInt *k, const BigInt *m);

/* Exponenciacion modular res = base^exp mod m (escalera de Montgomery, 256 bits) */
void bigint_exp_mod(BigInt *res, const BigInt *base, const BigInt *exp, const BigInt *m);

/*
 * Inverso modular por Pequeno Teorema de Fermat: res = k^(m-2) mod m.
 * Valido para modulo primo (p y n en P-256). Verifica k*res == 1 (mod m)
 * y devuelve 0 si no existe inverso.
 */
int  bigint_inv_mod_fermat(BigInt *res, const BigInt *k, const BigInt *m);

/* Generacion Aleatoria Criptografica en Rango [min, max] */
int bigint_random_range(BigInt *out, const BigInt *min, const BigInt *max);


/* ========================================================================= */
/*                          FUNCION HASH SHA-256                             */
/* ========================================================================= */

typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t  buffer[64];
} sha256_ctx;

void sha256_init(sha256_ctx *ctx);
void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len);
void sha256_final(sha256_ctx *ctx, uint8_t hash[32]);
void sha256_hash(const uint8_t *data, size_t len, uint8_t hash[32]);
void sha256_to_bigint(const uint8_t hash[32], BigInt *out);

/* HMAC-SHA256 (RFC 2104) */
void hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t out[32]);

/* Entropia del Sistema */
int cryptolib_random_bytes(uint8_t *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTOLIB_LIBCRYPT_H */
