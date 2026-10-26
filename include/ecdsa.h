#ifndef CRYPTOLIB_ECDSA_H
#define CRYPTOLIB_ECDSA_H

#include "libcrypt.h" /* Cabecera principal de CryptoLib (BigInt, Hash, etc.) */

#ifdef __cplusplus
extern "C" {
#endif

/* 1. Representacion de un punto (x, y) en coordenadas afines sobre F_p */
typedef struct {
    BigInt x;
    BigInt y;
    int is_infinity; /* 1 si representa el punto en el infinito (O), 0 en caso contrario */
} ECPoint;

/* 2. Parametros de dominio de la curva eliptica (ej. NIST P-256) */
typedef struct {
    BigInt p; /* Primo del campo finito F_p */
    BigInt a; /* Coeficiente 'a' de la curva */
    BigInt b; /* Coeficiente 'b' de la curva */
    ECPoint G; /* Punto generador base G = (Gx, Gy) */
    BigInt n; /* Orden primo del punto generador G */
} ECCurve;

/* 3. Estructura de la Firma Digital ECDSA */
typedef struct {
    BigInt r;
    BigInt s;
} ECDSASignature;

/* Prototipos de funciones del modulo requeridos por la especificacion */
void ec_init_p256(ECCurve *curve);
void ec_point_add(const ECCurve *curve, const ECPoint *P, const ECPoint *Q, ECPoint *R);
void ec_point_double(const ECCurve *curve, const ECPoint *P, ECPoint *R);
void ec_scalar_mul(const ECCurve *curve, const BigInt k, const ECPoint *P, ECPoint *R);

int ecdsa_keygen(const ECCurve *curve, BigInt priv_d, ECPoint *pub_Q);
int ecdsa_sign(const ECCurve *curve, const BigInt priv_d, const BigInt hash_e, ECDSASignature *sig);
int ecdsa_verify(const ECCurve *curve, const ECPoint *pub_Q, const BigInt hash_e, const ECDSASignature *sig);

/* Funciones auxiliares para validacion CAVP e interoperabilidad */
int ecdsa_sign_with_k(const ECCurve *curve, const BigInt priv_d, const BigInt hash_e, const BigInt k, ECDSASignature *sig);
int ecdsa_point_is_on_curve(const ECCurve *curve, const ECPoint *P);
int ecdsa_generate_keypair(const ECCurve *curve, BigInt *priv_d, ECPoint *pub_Q);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTOLIB_ECDSA_H */
