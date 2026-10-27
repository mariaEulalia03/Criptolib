# CryptoLib — Resultados de las Pruebas de Validación ECDSA

**Proyecto:** Implementación ECDSA P-256 (NIST FIPS 186-5 / SP 800-186 / FIPS 180-4)
**Fecha de ejecución:** 27 de octubre de 2026

---

## 1. Entorno de ejecución

| Elemento | Valor |
|---|---|
| Sistema | WSL2 — `Linux 6.6.87.2-microsoft-standard-WSL2` (Ubuntu 24.04) |
| Compilador | `gcc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0` |
| Build | `GNU Make 4.3` |
| Banderas | `-Wall -Wextra -O2 -Iinclude` |
| Resultado del build | **Sin warnings ni errores** |

Comando reproducible:

```bash
wsl -d Ubuntu -- bash -lc "cd /mnt/c/Users/maria/Downloads/Criptolib && make clean && make all && ./build/test_ecdsa"
```

---

## 2. Resumen general

| Fase | Contenido | Pruebas | Superadas | Fallidas |
|---|---|---:|---:|---:|
| Fase 0 | KAT de SHA-256 (FIPS 180-4) e incremental | 5 | 5 | 0 |
| Fase 0 | Pruebas unitarias de aritmética BigInt | 18 | 18 | 0 |
| Fase 1 y 2 | Inicialización y aritmética de puntos P-256 | 5 | 5 | 0 |
| Fase 3 | Vectores oficiales NIST CAVP | 5 | 5 | 0 |
| Fase 4 | Flujo completo y pruebas de seguridad | 6 | 6 | 0 |
| Fase 5 | Validación canónica y casos borde | 9 | 9 | 0 |
| **Total** | | **48** | **48** | **0** |

Código de salida del ejecutable: **0** (éxito).

---

## 3. Salida completa del banco de pruebas

```text
=================================================================
   CRYPTOLIB: BANCO DE PRUEBAS DE VALIDACION DEL ESTANDAR ECDSA
   NIST FIPS PUB 186-5 / NIST SP 800-186 / CURVE P-256 (SECP256R1)
=================================================================

=== FASE 0: Vectores de Prueba SHA-256 (FIPS 180-4) ===
  [PASS] SHA-256 KAT: "(cadena vacia)"
  [PASS] SHA-256 KAT: "abc"
  [PASS] SHA-256 KAT: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
  [PASS] SHA-256 KAT: "The quick brown fox jumps over the lazy dog"
  [PASS] SHA-256: procesamiento incremental coincide con sha256_hash

=== FASE 0: Pruebas Unitarias de Aritmetica BigInt ===
  [PASS] BigInt: suma propaga el acarreo entre palabras
  [PASS] BigInt: resta recupera el valor original
  [PASS] BigInt: resta con minuendo menor es rechazada (a >= b)
  [PASS] BigInt: multiplicacion de 64 x 64 bits es exacta
  [PASS] BigInt: division cumple a = q*b + r con r < b
  [PASS] BigInt: modulo coincide con el resto de la division
  [PASS] BigInt: inverso modular 7^-1 mod 13 = 2
  [PASS] BigInt: inverso modular inexistente devuelve error (modulo par)
  [PASS] BigInt: inverso modular inexistente devuelve error (mcd > 1)
  [PASS] BigInt: desplazamientos izquierda/derecha son reversibles
  [PASS] BigInt: conversion bytes <-> BigInt es reversible
  [PASS] BigInt: parseo hexadecimal con prefijo 0x
  [PASS] BigInt: hex con caracter invalido es rechazado
  [PASS] BigInt: cadena hexadecimal vacia es rechazada
  [PASS] BigInt: hex de mas de 640 bits es rechazado (sin truncamiento)
  [PASS] BigInt: hex de 160 digitos (640 bits) es aceptado
  [PASS] BigInt: muestreo aleatorio en [1, n-1] respeta el rango
  [PASS] BigInt: rango degenerado [1, 1] devuelve el limite

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
    Clave Privada (d): 0x395D4F2C19FC928F2C81C368582C039157800E7A0935136A323D23BF648442B6
    Clave Publica (Q.x): 0xCB082F04C470744C1EB6BB5B6228AFE0DA7AA72AAFDBBBAA29047CE56FE9196E
    Clave Publica (Q.y): 0x26BB9A65DE609DAE3837824D785BD9B3C5018E0736C7CDFF00C9137CA22E248A
    Mensaje a firmar: "Universidad de Cuenca - Seguridad Informatica - ECDSA CryptoLib 2026"
    Hash SHA-256 (e): 0x62ABDC100724792DA4F388285A170D8AEB7154653E267E25342941B901EF1ACF
  [PASS] Firma digital del mensaje original generada exitosamente
    Firma r: 0x42B3F23A4C97BD1FFDA6D5C98907CF618DD724E8A66ACF910E605456DC715B17
    Firma s: 0x7F5DC2B5D49B9746D5C8011BCDADB468CBD20F5C02D9A97D05FBE23E6EEC7587
  [PASS] Verificacion de autenticidad e integridad del mensaje (Aceptada)
  [PASS] Deteccion de manipulacion: mensaje alterado fue RECHAZADO
  [PASS] Proteccion de identidad: firma verificada con clave ajena fue RECHAZADA
  [PASS] Deteccion de firma adulterada (s modificado) fue RECHAZADA

=== FASE 5: Validacion Canonica y Casos Borde ===
  [PASS] Punto con x >= p es rechazado por la validacion canonica
  [PASS] ecdsa_verify rechaza una clave publica no canonica (x + p)
  [PASS] ecdsa_verify rechaza una clave publica no canonica (y + p)
  [PASS] ecdsa_verify rechaza r = 0
  [PASS] ecdsa_verify rechaza s = 0
  [PASS] ecdsa_verify rechaza s fuera del rango [1, n-1]
  [PASS] ecdsa_keygen rechaza d = 0
  [PASS] ecdsa_keygen rechaza d = n
  [PASS] ecdsa_verify rechaza la clave publica en el infinito

-----------------------------------------------------------------
RESUMEN DE PRUEBAS:
  Superadas: 48
  Fallidas:  0
-----------------------------------------------------------------
```

---

## 4. Validación con vector oficial NIST CAVP

Vector de la suite ECDSA P-256 / SHA-256 (FIPS 186-4/5):

| Parámetro | Valor |
|---|---|
| Clave privada d | `C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721` |
| Nonce k | `A6FE30047443EE12746441364D3E5B191435A942F84369992999F3565FB05A1F` |
| Hash e | `1AAB2E8797DBEFE22B675EB3FB917A85380C0DBE2EAF834E6D06058467BE7786` |
| r esperado | `614B38169454720149B2C66C185AAB68563CDB9C2220A858ED8318A354AFCAD4` |
| s esperado | `36AE7E05B4016D5DF650C22F3CE0D3EB84111A6021B5C79FEC56C2E64CA8FFEF` |

**Resultado:** r y s calculados coinciden **bit a bit** con los esperados, y `ecdsa_verify` acepta la firma (v = r). Esto valida conjuntamente la aritmética de campo, la multiplicación escalar, el inverso modular y el orden de las operaciones.
---

## 5. Prueba de extremo a extremo con la CLI

**1) Generación de claves**

```text
$ ./build/ecdsa_cli keygen
=== PAR DE CLAVES ECDSA P-256 GENERADO ===
Clave Privada (d) : 6D9A69014FD79194627F66A672F91A00B326960EC1D5752E48196BE4387DFA5E
Clave Publica Q.x : FB7B990F8CE8139148FEACC2B61D0616F01F8A5B4ACA4D64ECE644CA488F5895
Clave Publica Q.y : BFF56CE7C049E66E10EF8EB6EE0A16565F609062AC5E559C61EE61A0E72F2911
```

**2) Firma del mensaje**

```text
$ ./build/ecdsa_cli sign 6D9A...FA5E ExamenFinal
=== FIRMA DIGITAL GENERADA ===
Mensaje         : ExamenFinal
Hash SHA-256 (e): 18E84E7712196D328A0718D56873AC6427919AAC80DE3136EF3923D4D1647738
Firma r         : 74E110F467B1F2DE448B6601674C0CD723C3FBC33685B17D6D628D6618D24C86
Firma s         : A75B9CB6C401FC011EECF1B54F5B1AB426B114A22F52824D1EBE117933BBAA81
```

**3) Verificación con la clave pública**

```text
$ ./build/ecdsa_cli verify FB7B...5895 BFF5...2911 74E1...4C86 A75B...AA81 ExamenFinal
[VALIDA] La firma digital es AUTENTICA e INTEGRA para el mensaje "ExamenFinal".
```

**4) Rechazo de entrada inválida**

```text
$ ./build/ecdsa_cli sign 0xZZ hola
Error: Clave privada hexadecimal invalida.
```

> Nota: (r, s) cambian en cada ejecución porque k se genera con el CSPRNG del sistema (comportamiento correcto según FIPS 186-5).

---

## 6. Pruebas de seguridad (resultados negativos esperados)

| Caso | Acción | Resultado |
|---|---|---|
| Mensaje manipulado | Verificar firma válida con otro mensaje | Rechazada |
| Clave ajena | Verificar firma con Q de otra identidad | Rechazada |
| Firma adulterada | s' = s + 1 | Rechazada |
| r = 0 o s = 0 | Firma con componente nulo | Rechazada |
| s ≥ n | Firma con s' = s + n | Rechazada |
| Clave no canónica | Qx' = Qx + p o Qy' = Qy + p | Rechazada |
| Clave privada inválida | d = 0, d = n | Rechazada |
| Clave en el infinito | Q = O | Rechazada |

---

## 7. Hallazgos relevantes durante las pruebas

1. **Bug en el inverso modular.** Las pruebas nuevas de BigInt detectaron que `bigint_inv_mod` devolvía un resultado incorrecto con módulo par (2 mod 4) y podía entrar en **bucle infinito** con entradas no coprimas y módulo impar (3 mod 9). Se corrigió añadiendo la restricción de módulo impar y la detección de u o v nulos.
2. **Truncamiento silencioso de hex.** Antes, una cadena de más de 160 dígitos se truncaba sin aviso; ahora se rechaza con código de error y el valor queda en cero.
3. **Claves públicas no canónicas.** La verificación aceptaba coordenadas x, y ≥ p porque la ecuación se evaluaba tras la reducción modular; ahora se valida 0 ≤ x, y < p.
4. **Compilación limpia.** Con `-Wall -Wextra` no se reportan advertencias en ninguno de los módulos.

---

## 8. Conclusión

La implementación reproduce exactamente un vector oficial NIST CAVP, satisface los controles geométricos y algebraicos de la curva P-256, y rechaza correctamente todos los escenarios de manipulación probados: **48 de 48 pruebas superadas, 0 fallidas**.

Las limitaciones conocidas (no *constant-time*, sin zeroización de secretos, sin serialización DER/PEM) están documentadas en `Funcionamiento_e_Implementacion.md` y no afectan al alcance académico de la especificación.