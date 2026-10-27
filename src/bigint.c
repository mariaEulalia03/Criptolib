#include "libcrypt.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#if defined(_WIN32)
#include <windows.h>
#include <wincrypt.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

/* Ajusta len eliminando palabras cero mas significativas */
static void bigint_normalize(BigInt *a) {
    while (a->len > 0 && a->limbs[a->len - 1] == 0) {
        a->len--;
    }
}

void bigint_init(BigInt *a) {
    memset(a->limbs, 0, sizeof(a->limbs));
    a->len = 0;
}

void bigint_zero(BigInt *a) {
    bigint_init(a);
}

void bigint_set_u32(BigInt *a, uint32_t val) {
    bigint_init(a);
    if (val != 0) {
        a->limbs[0] = val;
        a->len = 1;
    }
}

void bigint_set_u64(BigInt *a, uint64_t val) {
    bigint_init(a);
    a->limbs[0] = (uint32_t)(val & 0xFFFFFFFFULL);
    a->limbs[1] = (uint32_t)(val >> 32);
    a->len = 2;
    bigint_normalize(a);
}

void bigint_copy(BigInt *dst, const BigInt *src) {
    if (dst != src) {
        memcpy(dst->limbs, src->limbs, sizeof(dst->limbs));
        dst->len = src->len;
    }
}

int bigint_cmp(const BigInt *a, const BigInt *b) {
    int max_len = (a->len > b->len) ? a->len : b->len;
    for (int i = max_len - 1; i >= 0; i--) {
        uint32_t aw = (i < a->len) ? a->limbs[i] : 0;
        uint32_t bw = (i < b->len) ? b->limbs[i] : 0;
        if (aw > bw) return 1;
        if (aw < bw) return -1;
    }
    return 0;
}

int bigint_is_zero(const BigInt *a) {
    for (int i = 0; i < a->len; i++) {
        if (a->limbs[i] != 0) return 0;
    }
    return 1;
}

int bigint_is_one(const BigInt *a) {
    if (a->len == 0) return 0;
    if (a->limbs[0] != 1) return 0;
    for (int i = 1; i < a->len; i++) {
        if (a->limbs[i] != 0) return 0;
    }
    return 1;
}

int bigint_is_even(const BigInt *a) {
    if (a->len == 0) return 1;
    return (a->limbs[0] & 1) == 0;
}

int bigint_bit_length(const BigInt *a) {
    if (a->len == 0) return 0;
    int top_idx = a->len - 1;
    uint32_t top = a->limbs[top_idx];
    if (top == 0) return 0;
    int bits = top_idx * 32;
    while (top > 0) {
        bits++;
        top >>= 1;
    }
    return bits;
}

int bigint_get_bit(const BigInt *a, int bit_idx) {
    if (bit_idx < 0) return 0;
    int word_idx = bit_idx / 32;
    int bit_offset = bit_idx % 32;
    if (word_idx >= a->len) return 0;
    return (a->limbs[word_idx] >> bit_offset) & 1;
}

void bigint_set_bit(BigInt *a, int bit_idx, int val) {
    if (bit_idx < 0) return;
    int word_idx = bit_idx / 32;
    int bit_offset = bit_idx % 32;
    if (word_idx >= BIGINT_WORDS) return;

    if (val) {
        a->limbs[word_idx] |= (1U << bit_offset);
        if (word_idx >= a->len) {
            a->len = word_idx + 1;
        }
    } else {
        a->limbs[word_idx] &= ~(1U << bit_offset);
        bigint_normalize(a);
    }
}

void bigint_shift_left(BigInt *res, const BigInt *a, int bits) {
    if (bits < 0) {
        bigint_shift_right(res, a, -bits);
        return;
    }
    if (bits == 0) {
        bigint_copy(res, a);
        return;
    }
    if (bigint_is_zero(a)) {
        bigint_zero(res);
        return;
    }

    int word_shift = bits / 32;
    int bit_shift = bits % 32;

    BigInt temp;
    bigint_init(&temp);

    uint64_t carry = 0;
    for (int i = 0; i < a->len && (i + word_shift) < BIGINT_WORDS; i++) {
        uint64_t cur = ((uint64_t)a->limbs[i] << bit_shift) | carry;
        temp.limbs[i + word_shift] = (uint32_t)(cur & 0xFFFFFFFFULL);
        carry = cur >> 32;
    }
    if (carry != 0 && (a->len + word_shift) < BIGINT_WORDS) {
        temp.limbs[a->len + word_shift] = (uint32_t)carry;
        temp.len = a->len + word_shift + 1;
    } else {
        temp.len = a->len + word_shift;
    }
    bigint_normalize(&temp);
    bigint_copy(res, &temp);
}

void bigint_shift_right(BigInt *res, const BigInt *a, int bits) {
    if (bits < 0) {
        bigint_shift_left(res, a, -bits);
        return;
    }
    if (bits == 0) {
        bigint_copy(res, a);
        return;
    }
    if (bigint_is_zero(a)) {
        bigint_zero(res);
        return;
    }

    int word_shift = bits / 32;
    int bit_shift = bits % 32;

    if (word_shift >= a->len) {
        bigint_zero(res);
        return;
    }

    BigInt temp;
    bigint_init(&temp);

    uint64_t high_carry = 0;
    for (int i = a->len - 1; i >= word_shift; i--) {
        uint64_t cur = ((uint64_t)a->limbs[i]) | (high_carry << 32);
        temp.limbs[i - word_shift] = (uint32_t)(cur >> bit_shift);
        high_carry = (uint32_t)(cur & ((1ULL << bit_shift) - 1ULL));
    }
    temp.len = a->len - word_shift;
    bigint_normalize(&temp);
    bigint_copy(res, &temp);
}

int bigint_add(BigInt *res, const BigInt *a, const BigInt *b) {
    BigInt temp;
    bigint_init(&temp);
    int max_len = (a->len > b->len) ? a->len : b->len;
    uint64_t carry = 0;

    for (int i = 0; i < max_len || carry; i++) {
        if (i >= BIGINT_WORDS) {
            return -1; /* Desbordamiento */
        }
        uint64_t sum = carry;
        if (i < a->len) sum += a->limbs[i];
        if (i < b->len) sum += b->limbs[i];
        temp.limbs[i] = (uint32_t)(sum & 0xFFFFFFFFULL);
        carry = sum >> 32;
        temp.len = i + 1;
    }
    bigint_normalize(&temp);
    bigint_copy(res, &temp);
    return 0;
}

int bigint_sub(BigInt *res, const BigInt *a, const BigInt *b) {
    if (bigint_cmp(a, b) < 0) {
        return -1; /* No soporta resultados negativos directamente */
    }
    BigInt temp;
    bigint_init(&temp);
    int64_t borrow = 0;

    for (int i = 0; i < a->len; i++) {
        int64_t diff = (int64_t)a->limbs[i] - borrow;
        if (i < b->len) {
            diff -= (int64_t)b->limbs[i];
        }
        if (diff < 0) {
            diff += 0x100000000LL;
            borrow = 1;
        } else {
            borrow = 0;
        }
        temp.limbs[i] = (uint32_t)(diff & 0xFFFFFFFFLL);
    }
    temp.len = a->len;
    bigint_normalize(&temp);
    bigint_copy(res, &temp);
    return 0;
}

void bigint_mul(BigInt *res, const BigInt *a, const BigInt *b) {
    if (bigint_is_zero(a) || bigint_is_zero(b)) {
        bigint_zero(res);
        return;
    }

    BigInt temp;
    bigint_init(&temp);

    for (int i = 0; i < a->len; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < b->len || carry; j++) {
            if ((i + j) >= BIGINT_WORDS) break;
            uint64_t cur = (uint64_t)temp.limbs[i + j] + carry;
            if (j < b->len) {
                cur += (uint64_t)a->limbs[i] * (uint64_t)b->limbs[j];
            }
            temp.limbs[i + j] = (uint32_t)(cur & 0xFFFFFFFFULL);
            carry = cur >> 32;
            if ((i + j + 1) > temp.len) {
                temp.len = i + j + 1;
            }
        }
    }
    bigint_normalize(&temp);
    bigint_copy(res, &temp);
}

void bigint_div(BigInt *q, BigInt *r, const BigInt *a, const BigInt *b) {
    if (bigint_is_zero(b)) {
        /* Division por cero */
        if (q) bigint_zero(q);
        if (r) bigint_zero(r);
        return;
    }

    if (bigint_cmp(a, b) < 0) {
        if (q) bigint_zero(q);
        if (r) bigint_copy(r, a);
        return;
    }

    BigInt rem;
    BigInt quotient;
    bigint_init(&rem);
    bigint_init(&quotient);

    int a_bits = bigint_bit_length(a);

    for (int i = a_bits - 1; i >= 0; i--) {
        bigint_shift_left(&rem, &rem, 1);
        if (bigint_get_bit(a, i)) {
            bigint_set_bit(&rem, 0, 1);
        }

        if (bigint_cmp(&rem, b) >= 0) {
            bigint_sub(&rem, &rem, b);
            bigint_set_bit(&quotient, i, 1);
        }
    }

    if (q) bigint_copy(q, &quotient);
    if (r) bigint_copy(r, &rem);
}

void bigint_mod(BigInt *res, const BigInt *a, const BigInt *m) {
    bigint_div(NULL, res, a, m);
}

void bigint_add_mod(BigInt *res, const BigInt *a, const BigInt *b, const BigInt *m) {
    BigInt sum;
    bigint_add(&sum, a, b);
    if (bigint_cmp(&sum, m) >= 0) {
        bigint_sub(res, &sum, m);
        if (bigint_cmp(res, m) >= 0) {
            bigint_mod(res, res, m);
        }
    } else {
        bigint_copy(res, &sum);
    }
}

void bigint_sub_mod(BigInt *res, const BigInt *a, const BigInt *b, const BigInt *m) {
    if (bigint_cmp(a, b) >= 0) {
        BigInt diff;
        bigint_sub(&diff, a, b);
        bigint_mod(res, &diff, m);
    } else {
        BigInt temp;
        bigint_add(&temp, a, m);
        bigint_sub(&temp, &temp, b);
        bigint_mod(res, &temp, m);
    }
}

void bigint_mul_mod(BigInt *res, const BigInt *a, const BigInt *b, const BigInt *m) {
    BigInt prod;
    bigint_mul(&prod, a, b);
    bigint_mod(res, &prod, m);
}

/*
 * Inversion Modular (NIST FIPS 186-5 Apendice B.2)
 * Algoritmo Binario de Maximo Comun Divisor Extendido sobre Enteros Positivos
 */
int bigint_inv_mod(BigInt *res, const BigInt *k, const BigInt *m) {
    if (bigint_is_zero(k) || bigint_is_zero(m)) {
        bigint_zero(res);
        return 0;
    }

    /*
     * El algoritmo binario de NIST B.2 asume modulo IMPAR (siempre cierto en
     * P-256, donde p y n son primos impares). Con modulo par la division
     * (x + m) / 2 no es exacta y el resultado seria incorrecto.
     */
    if (bigint_is_even(m)) {
        bigint_zero(res);
        return 0;
    }

    BigInt u, v, x1, x2;
    bigint_copy(&u, k);
    bigint_copy(&v, m);
    bigint_set_u32(&x1, 1);
    bigint_zero(&x2);

    while (!bigint_is_one(&u) && !bigint_is_one(&v)) {
        /* Si u o v llegan a cero, mcd(k, m) > 1: el inverso no existe */
        if (bigint_is_zero(&u) || bigint_is_zero(&v)) {
            bigint_zero(res);
            return 0;
        }

        while (bigint_is_even(&u)) {
            bigint_shift_right(&u, &u, 1);
            if (bigint_is_even(&x1)) {
                bigint_shift_right(&x1, &x1, 1);
            } else {
                bigint_add(&x1, &x1, m);
                bigint_shift_right(&x1, &x1, 1);
            }
        }

        while (bigint_is_even(&v)) {
            bigint_shift_right(&v, &v, 1);
            if (bigint_is_even(&x2)) {
                bigint_shift_right(&x2, &x2, 1);
            } else {
                bigint_add(&x2, &x2, m);
                bigint_shift_right(&x2, &x2, 1);
            }
        }

        if (bigint_cmp(&u, &v) >= 0) {
            bigint_sub(&u, &u, &v);
            if (bigint_cmp(&x1, &x2) >= 0) {
                bigint_sub(&x1, &x1, &x2);
            } else {
                BigInt temp;
                bigint_add(&temp, &x1, m);
                bigint_sub(&x1, &temp, &x2);
            }
        } else {
            bigint_sub(&v, &v, &u);
            if (bigint_cmp(&x2, &x1) >= 0) {
                bigint_sub(&x2, &x2, &x1);
            } else {
                BigInt temp;
                bigint_add(&temp, &x2, m);
                bigint_sub(&x2, &temp, &x1);
            }
        }
    }

    if (bigint_is_one(&u)) {
        bigint_mod(res, &x1, m);
    } else if (bigint_is_one(&v)) {
        bigint_mod(res, &x2, m);
    } else {
        bigint_zero(res);
        return 0; /* Inverso no existe */
    }
    return 1;
}

/*
 * Parseo desde cadena hexadecimal.
 * Devuelve 0 en exito, -1 si la cadena es vacia, contiene un caracter
 * no hexadecimal o excede la capacidad maxima (BIGINT_WORDS * 8 digitos).
 * Ante cualquier error el BigInt de salida queda en cero, evitando que un
 * valor truncado se use silenciosamente como clave o firma.
 */
int bigint_from_hex(BigInt *a, const char *hex_str) {
    bigint_init(a);
    if (!hex_str) return -1;

    /* Ignora prefijo 0x o 0X si existe */
    if (hex_str[0] == '0' && (hex_str[1] == 'x' || hex_str[1] == 'X')) {
        hex_str += 2;
    }

    const int max_digits = (int)(BIGINT_WORDS * 8);
    int digits = 0;

    for (const char *p = hex_str; *p != '\0'; p++) {
        unsigned char c = (unsigned char)*p;
        if (isspace(c)) continue; /* Ignora espacios en blanco */

        int val;
        if (c >= '0' && c <= '9') val = c - '0';
        else if (c >= 'a' && c <= 'f') val = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') val = c - 'A' + 10;
        else { /* Caracter invalido */
            bigint_zero(a);
            return -1;
        }

        /* Rechaza desbordamiento en lugar de truncar los bits altos */
        if (++digits > max_digits) {
            bigint_zero(a);
            return -1;
        }

        bigint_shift_left(a, a, 4);
        a->limbs[0] |= (uint32_t)val;
        if (a->len == 0 && val != 0) a->len = 1;
    }

    if (digits == 0) { /* Cadena vacia o solo espacios */
        bigint_zero(a);
        return -1;
    }

    bigint_normalize(a);
    return 0;
}

/* Conversion a cadena hexadecimal en formato big-endian */
void bigint_to_hex(const BigInt *a, char *out_buf, size_t max_len) {
    if (!out_buf || max_len == 0) return;
    if (bigint_is_zero(a)) {
        snprintf(out_buf, max_len, "0");
        return;
    }

    size_t out_idx = 0;
    int first = 1;
    for (int i = a->len - 1; i >= 0; i--) {
        char seg[16];
        if (first) {
            snprintf(seg, sizeof(seg), "%X", a->limbs[i]);
            first = 0;
        } else {
            snprintf(seg, sizeof(seg), "%08X", a->limbs[i]);
        }
        size_t seg_len = strlen(seg);
        if (out_idx + seg_len < max_len) {
            memcpy(out_buf + out_idx, seg, seg_len);
            out_idx += seg_len;
        } else {
            break;
        }
    }
    out_buf[out_idx] = '\0';
}

int bigint_from_bytes(BigInt *a, const uint8_t *bytes, size_t len) {
    bigint_init(a);
    if (!bytes || len == 0) return 0;

    for (size_t i = 0; i < len; i++) {
        bigint_shift_left(a, a, 8);
        a->limbs[0] |= bytes[i];
        if (a->len == 0 && bytes[i] != 0) a->len = 1;
    }
    bigint_normalize(a);
    return 0;
}

void bigint_to_bytes(const BigInt *a, uint8_t *bytes, size_t len) {
    if (!bytes || len == 0) return;
    memset(bytes, 0, len);

    BigInt temp;
    bigint_copy(&temp, a);

    for (size_t i = 0; i < len; i++) {
        bytes[len - 1 - i] = (uint8_t)(temp.limbs[0] & 0xFF);
        bigint_shift_right(&temp, &temp, 8);
    }
}

/* Obtener bytes criptograficos aleatorios del sistema */
int cryptolib_random_bytes(uint8_t *buf, size_t len) {
#if defined(_WIN32)
    HCRYPTPROV hProv = 0;
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
        return 0;
    }
    BOOL ok = CryptGenRandom(hProv, (DWORD)len, buf);
    CryptReleaseContext(hProv, 0);
    return ok ? 1 : 0;
#else
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return 0;
    size_t read_bytes = 0;
    while (read_bytes < len) {
        ssize_t r = read(fd, buf + read_bytes, len - read_bytes);
        if (r <= 0) {
            close(fd);
            return 0;
        }
        read_bytes += (size_t)r;
    }
    close(fd);
    return 1;
#endif
}

/* Generar un BigInt aleatorio en el rango [min, max] mediante muestreo por rechazo */
int bigint_random_range(BigInt *out, const BigInt *min, const BigInt *max) {
    if (bigint_cmp(min, max) > 0) return 0;
    if (bigint_cmp(min, max) == 0) {
        bigint_copy(out, min);
        return 1;
    }

    BigInt range;
    bigint_sub(&range, max, min);
    int bit_len = bigint_bit_length(&range);
    int byte_len = (bit_len + 7) / 8;
    if (byte_len > (int)(BIGINT_WORDS * sizeof(uint32_t))) return 0;

    uint8_t buffer[BIGINT_WORDS * sizeof(uint32_t)];
    BigInt candidate;

    for (int attempts = 0; attempts < 1000; attempts++) {
        if (!cryptolib_random_bytes(buffer, byte_len)) {
            return 0;
        }
        bigint_from_bytes(&candidate, buffer, byte_len);
        /* Enmascarar bits superiores si bit_len no es multiplo de 8 */
        int excess_bits = (byte_len * 8) - bit_len;
        if (excess_bits > 0 && candidate.len > 0) {
            bigint_shift_right(&candidate, &candidate, excess_bits);
        }

        if (bigint_cmp(&candidate, &range) <= 0) {
            bigint_add(out, &candidate, min);
            return 1;
        }
    }
    return 0;
}
