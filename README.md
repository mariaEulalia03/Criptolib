# CryptoLib: Implementación del Estándar ECDSA en C

**Universidad de Cuenca**  
**Facultad de Ingeniería – Computación**  
**Materia:** Seguridad Informática  
**Autores:** Joseline Banegas, Maria Lojano, Adrian Muñoz

---

## 1. Descripción del Proyecto

Este repositorio contiene la implementación completa en lenguaje C del **Algoritmo de Firma Digital de Curva Elíptica (ECDSA)** bajo los estándares internacionales:

- **NIST FIPS PUB 186-5**: *Digital Signature Standard (DSS)*.
- **NIST SP 800-186**: *Recommendations for Discrete Logarithm-based Cryptography: Elliptic Curve Domain Parameters* (Curva P-256 / secp256r1).
- **NIST FIPS PUB 180-4**: *Secure Hash Standard (SHS)* (SHA-256).

El desarrollo se construyó siguiendo estrictamente el [Documento de Especificación y Diseño](./Banegas-Lojano-Munoz_Especificacion_y_Diseno_ECDSA_CryptoLib.pdf) del equipo.

---

## 2. Estructura del Directorio

```text
Trabajo SI/
├── Makefile                                                          # Script de construcción y automatización
├── README.md                                                         # Documentación del proyecto
├── Banegas-Lojano-Munoz_Especificacion_y_Diseno_ECDSA_CryptoLib.pdf # Documento oficial de diseño
├── docs/
│   ├── Funcionamiento_e_Implementacion.md # Funcionamiento, matemáticas y proceso de implementación
│   └── Resultados_de_Pruebas.md           # Resultados de las 48 pruebas de validación
├── include/
│   ├── libcrypt.h      # Infraestructura modular: aritmética BigInt y SHA-256
│   └── ecdsa.h         # Estructuras afines (ECPoint, ECCurve, ECDSASignature) y prototipos
├── src/
│   ├── bigint.c        # Aritmética de precisión arbitraria e inverso modular (NIST B.2)
│   ├── sha256.c        # Función resumen criptográfica SHA-256 y CSPRNG
│   ├── ecdsa.c         # Primitivas geométricas y algoritmos ECDSA (keygen, sign, verify)
│   └── cli.c           # Herramienta de línea de comandos para firma y verificación
└── tests/
    └── test_ecdsa.c    # Suite de pruebas automatizadas con vectores NIST CAVP
```

---

## 3. Hoja de Ruta e Hitos Desarrollados

### Fase 1: Inicialización de Constantes (`ec_init_p256`)

- Carga en memoria `BigInt` de los parámetros de dominio de **Curve P-256** según la Sección 3.2.1.3 del NIST SP 800-186:
   - Primo $p = 2^{256} - 2^{224} + 2^{192} + 2^{96} - 1$
   - Coeficientes $a = -3 \pmod p$ y $b$
   - Punto generador base $G = (G_x, G_y)$
   - Orden primo del grupo $n$

### Fase 2: Aritmética Geométrica en Coordenadas Afines

- `ec_point_double`: Duplicación de puntos usando la pendiente tangente $\lambda = (3x_1^2 + a)(2y_1)^{-1} \pmod p$.
- `ec_point_add`: Adición de puntos secantes $\lambda = (y_2 - y_1)(x_2 - x_1)^{-1} \pmod p$.
- `ec_scalar_mul`: Multiplicación escalar $Q = [k]P$ mediante el algoritmo binario __Double-and-Add__ (MSB a LSB).
- **Prueba de Control 1**:
   - $\checkmark$ Verificación de que $G \in E(\mathbb{F}_p)$.
   - $\checkmark$ Verificación $[1]G = G$.
   - $\checkmark$ Verificación de que $[2]G$ coincide con el vector oficial $2G$.
   - $\checkmark$ Verificación de que $[n]G = \mathcal{O}$ (punto en el infinito).

### Fase 3: Primitivas Criptográficas de ECDSA

- `ecdsa_keygen`: Generación y validación del par de claves $(d, Q)$ tal que $Q = [d]G$.
- `ecdsa_sign`: Generación de firma digital $(r, s)$ con $k \in_R [1, n-1]$ y cálculo del inverso modular $k^{-1} \pmod n$ vía el algoritmo extendido binario (NIST FIPS 186-5 Apéndice B.2).
- `ecdsa_verify`: Verificación estricta mediante $X = [u_1]G + [u_2]Q$, validando que $v = X_x \pmod n == r$.
- **Prueba de Control 2**:
   - $\checkmark$ Validación bit a bit de $(r, s)$ contra vectores oficiales del **NIST CAVP (Cryptographic Algorithm Validation Program)**.

### Fase 4: Integración, Makefile y CLI

- Compilación de la librería estática `build/libcrypt.a`.
- Suite de pruebas de seguridad:
   - $\checkmark$ Detección de mensajes manipulados (Tampering).
   - $\checkmark$ Detección de firmas con clave ajena (Wrong Key).
   - $\checkmark$ Detección de componentes adulterados en $(r, s)$.
- Validaciones endurecidas: coordenadas canónicas de clave pública ($x, y < p$), parámetros de firma en $[1, n-1]$ y rechazo de entradas hexadecimales inválidas o mayores a 640 bits.
- Pruebas unitarias de SHA-256 (KAT FIPS 180-4) y de la aritmética BigInt.

- CLI interactivo `build/ecdsa_cli` para generación de claves, firma y verificación.

---

## 4. Instrucciones de Compilación y Ejecución

El proyecto puede compilarse en Linux/WSL (o Windows con MinGW/GCC):

### Compilar Todo (Librería, Tests y CLI)

```bash
make all
```

### Ejecutar la Suite de Pruebas Automatizadas

```bash
make run
```

Salida esperada:

```text
=================================================================
   CRYPTOLIB: BANCO DE PRUEBAS DE VALIDACION DEL ESTANDAR ECDSA  
   NIST FIPS PUB 186-5 / NIST SP 800-186 / CURVE P-256 (SECP256R1) 
=================================================================

=== FASE 0: SHA-256 (FIPS 180-4) y Arimetica BigInt (pruebas unitarias) ===
  [PASS] SHA-256 KAT: cadena vacia, "abc", bloque multiple y frase de referencia
  [PASS] SHA-256: procesamiento incremental coincide con sha256_hash
  [PASS] BigInt: suma con acarreo, resta reversible y rechazo de a < b
  [PASS] BigInt: multiplicacion 64x64 y division a = q*b + r
  [PASS] BigInt: inverso modular valido e inexistente (modulo par / mcd > 1)
  [PASS] BigInt: desplazamientos, bytes y prefijo 0x
  [PASS] BigInt: rechazo de hex invalido, vacio y mayor a 640 bits
  [PASS] BigInt: muestreo aleatorio dentro de [1, n-1]

=== FASE 1 Y 2: Inicializacion y Aritmetica de Puntos P-256 ===
  [PASS] Punto generador base G pertenece a Curve P-256
  [PASS] Multiplicacion escalar [1]G coincide exactamente con G
  [PASS] Duplicacion de punto ec_point_double(G) coincide bit a bit con 2G oficial
  [PASS] Equivalencia entre ec_point_double(G) y ec_scalar_mul(2, G)
  [PASS] Orden primo [n]G resulta en el punto en el infinito (O)

=== FASE 3: Validacion con Vectores Oficiales del NIST CAVP ===
  [PASS] Generacion y validacion de clave publica NIST CAVP Q = [d]G
  [PASS] Generacion de firma con k fijo (NIST CAVP)
  [PASS] Componente de firma 'r' coincide bit a bit con CAVP
  [PASS] Componente de firma 's' coincide bit a bit con CAVP
  [PASS] Verificacion ecdsa_verify exitosa con vector CAVP (v == r)

=== FASE 4: Flujo Completo con Mensaje Real y Pruebas de Seguridad ===
  [PASS] Generacion de nuevo par de claves aleatorias (d, Q) mediante CSPRNG
  [PASS] Firma digital del mensaje original generada exitosamente
  [PASS] Verificacion de autenticidad e integridad del mensaje (Aceptada)
  [PASS] Deteccion de manipulacion: mensaje alterado fue RECHAZADO
  [PASS] Proteccion de identidad: firma verificada con clave ajena fue RECHAZADA
  [PASS] Deteccion de firma adulterada (s modificado) fue RECHAZADA

=== FASE 5: Validacion Canonica y Casos Borde ===
  [PASS] Punto con x >= p es rechazado por la validacion canonica
  [PASS] ecdsa_verify rechaza clave publica no canonica (x + p, y + p)
  [PASS] ecdsa_verify rechaza r = 0, s = 0 y s fuera de [1, n-1]
  [PASS] ecdsa_keygen rechaza d = 0 y d = n
  [PASS] ecdsa_verify rechaza la clave publica en el infinito

-----------------------------------------------------------------
RESUMEN DE PRUEBAS: Superadas: 48 | Fallidas: 0
-----------------------------------------------------------------
```

---

## 5. Guía de Uso de la Herramienta CLI (`ecdsa_cli`)

### 1. Generar un nuevo par de claves

```bash
./build/ecdsa_cli keygen
```

*Salida:*

```text
=== PAR DE CLAVES ECDSA P-256 GENERADO ===
Clave Privada (d) : C980A84AB9771D3586BA4D6C5A38249B73EB2DF3C07A250450B40FAF7A669C13
Clave Publica Q.x : 79950CC76E2582824A74ABDB2C793F1B60460282DFC97C2A05A81FFE812C55AD
Clave Publica Q.y : 70152DC04EF79FDE6953E8B031D31B97F9077A68E505605AE2DC80F64A4E3813
```

### 2. Firmar un mensaje con la clave privada

```bash
./build/ecdsa_cli sign C980A84AB9771D3586BA4D6C5A38249B73EB2DF3C07A250450B40FAF7A669C13 "Examen de Seguridad Informatica"
```

*Salida:*

```text
=== FIRMA DIGITAL GENERADA ===
Mensaje         : Examen de Seguridad Informatica
Hash SHA-256 (e): 34B19958064F25091BF3E3C57B4397C1BD0BE1B33B104F5EBDDF14D5220B8F42
Firma r         : A1E84218C838F5A6D63E66F42D5F348F567634C2B04E37B34237190F623F821A
Firma s         : 95E12E57041BA890B42A42F38760B12F016259021CD39B5241C7C1EF41508EF5
```

### 3. Verificar la firma digital con la clave pública

```bash
./build/ecdsa_cli verify 79950CC76E2582824A74ABDB2C793F1B60460282DFC97C2A05A81FFE812C55AD 70152DC04EF79FDE6953E8B031D31B97F9077A68E505605AE2DC80F64A4E3813 A1E84218C838F5A6D63E66F42D5F348F567634C2B04E37B34237190F623F821A 95E12E57041BA890B42A42F38760B12F016259021CD39B5241C7C1EF41508EF5 "Examen de Seguridad Informatica"
```

*Salida:*

```text
[VALIDA] La firma digital es AUTENTICA e INTEGRA para el mensaje "Examen de Seguridad Informatica".
```
