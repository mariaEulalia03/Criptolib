#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "ecdsa.h"

static void print_usage(const char *prog) {
    printf("Uso: %s <comando> [opciones]\n\n", prog);
    printf("Comandos disponibles:\n");
    printf("  keygen                                      Genera un nuevo par de claves (d, Q)\n");
    printf("  sign   <priv_d_hex> <mensaje>               Firma un mensaje de texto\n");
    printf("  verify <pub_Qx_hex> <pub_Qy_hex> <r_hex> <s_hex> <mensaje>\n");
    printf("                                              Verifica una firma digital ECDSA\n");
}

/* Concatena los argumentos restantes a partir del indice 'start' */
static char *combine_args(int argc, char *argv[], int start) {
    if (start >= argc) return strdup("");
    size_t total_len = 0;
    for (int i = start; i < argc; i++) {
        total_len += strlen(argv[i]) + 1;
    }
    char *buf = (char *)malloc(total_len + 1);
    if (!buf) return NULL;
    buf[0] = '\0';
    for (int i = start; i < argc; i++) {
        strcat(buf, argv[i]);
        if (i < argc - 1) {
            strcat(buf, " ");
        }
    }
    return buf;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    ECCurve curve;
    ec_init_p256(&curve);

    const char *cmd = argv[1];

    if (strcmp(cmd, "keygen") == 0) {
        BigInt priv_d;
        ECPoint pub_Q;
        if (!ecdsa_generate_keypair(&curve, &priv_d, &pub_Q)) {
            fprintf(stderr, "Error al generar par de claves.\n");
            return 1;
        }

        char hex_d[256], hex_qx[256], hex_qy[256];
        bigint_to_hex(&priv_d, hex_d, sizeof(hex_d));
        bigint_to_hex(&pub_Q.x, hex_qx, sizeof(hex_qx));
        bigint_to_hex(&pub_Q.y, hex_qy, sizeof(hex_qy));

        printf("=== PAR DE CLAVES ECDSA P-256 GENERADO ===\n");
        printf("Clave Privada (d) : %s\n", hex_d);
        printf("Clave Publica Q.x : %s\n", hex_qx);
        printf("Clave Publica Q.y : %s\n", hex_qy);
        return 0;
    }
    else if (strcmp(cmd, "sign") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Uso: %s sign <priv_d_hex> <mensaje>\n", argv[0]);
            return 1;
        }

        BigInt priv_d;
        if (bigint_from_hex(&priv_d, argv[2]) != 0) {
            fprintf(stderr, "Error: Clave privada hexadecimal invalida.\n");
            return 1;
        }

        char *msg = combine_args(argc, argv, 3);
        if (!msg) {
            fprintf(stderr, "Error de memoria.\n");
            return 1;
        }

        uint8_t hash[32];
        sha256_hash((const uint8_t *)msg, strlen(msg), hash);

        BigInt hash_e;
        sha256_to_bigint(hash, &hash_e);

        ECDSASignature sig;
        if (!ecdsa_sign(&curve, priv_d, hash_e, &sig)) {
            fprintf(stderr, "Error al generar la firma.\n");
            free(msg);
            return 1;
        }

        char hex_r[256], hex_s[256], hex_e[256];
        bigint_to_hex(&sig.r, hex_r, sizeof(hex_r));
        bigint_to_hex(&sig.s, hex_s, sizeof(hex_s));
        bigint_to_hex(&hash_e, hex_e, sizeof(hex_e));

        printf("=== FIRMA DIGITAL GENERADA ===\n");
        printf("Mensaje         : %s\n", msg);
        printf("Hash SHA-256 (e): %s\n", hex_e);
        printf("Firma r         : %s\n", hex_r);
        printf("Firma s         : %s\n", hex_s);

        free(msg);
        return 0;
    }
    else if (strcmp(cmd, "verify") == 0) {
        if (argc < 7) {
            fprintf(stderr, "Uso: %s verify <pub_Qx_hex> <pub_Qy_hex> <r_hex> <s_hex> <mensaje>\n", argv[0]);
            return 1;
        }

        ECPoint pub_Q;
        pub_Q.is_infinity = 0;
        if (bigint_from_hex(&pub_Q.x, argv[2]) != 0 || bigint_from_hex(&pub_Q.y, argv[3]) != 0) {
            fprintf(stderr, "Error: Coordenadas de clave publica invalidas.\n");
            return 1;
        }

        ECDSASignature sig;
        if (bigint_from_hex(&sig.r, argv[4]) != 0 || bigint_from_hex(&sig.s, argv[5]) != 0) {
            fprintf(stderr, "Error: Componentes de firma invalidos.\n");
            return 1;
        }

        char *msg = combine_args(argc, argv, 6);
        if (!msg) {
            fprintf(stderr, "Error de memoria.\n");
            return 1;
        }

        uint8_t hash[32];
        sha256_hash((const uint8_t *)msg, strlen(msg), hash);

        BigInt hash_e;
        sha256_to_bigint(hash, &hash_e);

        int ok = ecdsa_verify(&curve, &pub_Q, hash_e, &sig);
        if (ok) {
            printf("[VALIDA] La firma digital es AUTENTICA e INTEGRA para el mensaje \"%s\".\n", msg);
            free(msg);
            return 0;
        } else {
            printf("[INVALIDA] La firma fue RECHAZADA para el mensaje \"%s\" (mensaje alterado o clave erronea).\n", msg);
            free(msg);
            return 2;
        }
    }
    else {
        print_usage(argv[0]);
        return 1;
    }
}
