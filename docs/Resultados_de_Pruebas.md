# CryptoLib — Resultados de las Pruebas de Validación ECDSA

**Proyecto:** Implementación ECDSA P-256 (NIST FIPS 186-5 / SP 800-186 / FIPS 180-4) con HMAC-SHA256 y RFC 6979
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
| Duración de la suite | **2,62 s** (60 pruebas) |

Comando reproducible:

```bash
wsl -d Ubuntu -- bash -lc "cd /mnt/c/Users/maria/Downloads/Criptolib && make clean && make all && ./build/test_ecdsa"
```

---

## 2. Resumen general

| Fase | Contenido | Pruebas | Superadas | Fallidas |
|---|---|---:|---:|---:|
| Fase 0 | KAT de SHA-256 (FIPS 180-4) e incremental | 5 | 5 | 0 |
| Fase 0 | HMAC-SHA256 con vectores RFC 4231 | 3 | 3 | 0 |
| Fase 0 | Pruebas unitarias de aritmética BigInt (incluye exp_mod y Fermat) | 22 | 22 | 0 |
| Fase 1 y 2 | Inicialización y aritmética de puntos P-256 (escalera) | 5 | 5 | 0 |
| Fase 3 | Vectores oficiales NIST CAVP | 5 | 5 | 0 |
| Fase 3B | Firma determinista RFC 6979 (P-256 / SHA-256) | 5 | 5 | 0 |
| Fase 4 | Flujo completo y pruebas de seguridad | 6 | 6 | 0 |
| Fase 5 | Validación canónica y casos borde | 9 | 9 | 0 |
| **Total** | | **60** | **60** | **0** |

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

=== FASE 0: HMAC-SHA256 (RFC 4231) ===
  [PASS] HMAC-SHA256 KAT 1 (RFC 4231): clave 0x0b x 20
  [PASS] HMAC-SHA256 KAT 2 (RFC 4231): clave corta "Jefe"
  [PASS] HMAC-SHA256 KAT 6 (RFC 4231): clave mayor a 64 bytes

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
  [PASS] BigInt: exponenciacion modular 2^10 mod 1000 y 3^7 mod 13
  [PASS] BigInt: inverso por Fermat 7^-1 mod 13 = 2
  [PASS] BigInt: inverso por Fermat rechaza 3 mod 9
  [PASS] BigInt: inverso por Fermat rechaza 2 mod 4
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

=== FASE 3B: Firma determinista RFC 6979 (P-256 / SHA-256) ===
  [PASS] RFC 6979: (r, s) deterministas coinciden con el vector "sample"
  [PASS] RFC 6979: firma determinista verificada con ecdsa_verify
  [PASS] RFC 6979: (r, s) deterministas coinciden con el vector "test"
  [PASS] RFC 6979: firma determinista verificada con ecdsa_verify
  [PASS] RFC 6979: dos firmas del mismo mensaje son identicas

=== FASE 4: Flujo Completo con Mensaje Real y Pruebas de Seguridad ===
  [PASS] Generacion de nuevo par de claves aleatorias (d, Q) mediante CSPRNG
    Clave Privada (d): 0x3FB76B2E0D5A7A373CB12DB81E6BCBB7BEC0048279828BF3B7DE6767822CF218
    Clave Publica (Q.x): 0x39C153C590DF60456024DFB1F03BC8EC80F5ABB71CF161243F4E14579A15E632
    Clave Publica (Q.y): 0x30629F0B26AE2B9CDE0B39D924FBE0F6C79DCB476D0997166F34B132BECEAB07
    Mensaje a firmar: "Universidad de Cuenca - Seguridad Informatica - ECDSA CryptoLib 2026"
    Hash SHA-256 (e): 0x62ABDC100724792DA4F388285A170D8AEB7154653E267E25342941B901EF1ACF
  [PASS] Firma digital del mensaje original generada exitosamente
    Firma r: 0x74B3C78D943BAFB2A9C9F099EE40FB46CDDE6CD0F9DC904E642E4A5593DEA75C
    Firma s: 0xAD20D009B7D149434C8A98FD6682B2942321F46CCDF61D7197E076E84161C856
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
  Superadas: 60
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

**Resultado:** r y s calculados coinciden **bit a bit** con los esperados, y `ecdsa_verify` acepta la firma (v = r). Esto valida la aritmética de campo, la escalera de Montgomery, el inverso de k y el orden de las operaciones.
---

## 5. Firma determinista RFC 6979 (P-256 / SHA-256)

Clave privada del Apéndice A.2.5 de RFC 6979:
`C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721`

| Mensaje | Componente | Valor esperado (RFC 6979) | Obtenido |
|---|---|---|---|
| "sample" | r | `EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716` | Coincide |
| "sample" | s | `F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8` | Coincide |
| "test" | r | `F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367` | Coincide |
| "test" | s | `019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083` | Coincide |

Además se comprueba que dos firmas consecutivas del mismo mensaje producen exactamente la misma (r, s), lo que confirma que k se deriva de HMAC-SHA256 (V/K) y no del CSPRNG.

### HMAC-SHA256 (RFC 4231)

| Caso | Clave | MAC esperado | Resultado |
|---|---|---|---|
| 1 | 0x0b × 20 | `B0344C61D8DB38535CA8AFCEAF0BF12B881DC200C9833DA726E9376C2E32CFF7` | Coincide |
| 2 | "Jefe" | `5BDCC146BF60754E6A042426089575C75A003F089D2739839DEC58B964EC3843` | Coincide |
| 6 | 0xaa × 131 | `60E431591EE0B67F0D8A26AACBF5B77F8E0BC6213728C5140546040F0EE37F54` | Coincide |

---

## 6. Prueba de extremo a extremo con la CLI

**1) Generación de claves**

```text
$ ./build/ecdsa_cli keygen
=== PAR DE CLAVES ECDSA P-256 GENERADO ===
Clave Privada (d) : 6D9A69014FD79194627F66A672F91A00B326960EC1D5752E48196BE4387DFA5E
Clave Publica Q.x : FB7B990F8CE8139148FEACC2B61D0616F01F8A5B4ACA4D64ECE644CA488F5895
Clave Publica Q.y : BFF56CE7C049E66E10EF8EB6EE0A16565F609062AC5E559C61EE61A0E72F2911
```

**2) Firma del mensaje (determinista)**

```text
$ ./build/ecdsa_cli sign 6D9A...FA5E ExamenFinal
=== FIRMA DIGITAL GENERADA ===
Mensaje         : ExamenFinal
Hash SHA-256 (e): 18E84E7712196D328A0718D56873AC6427919AAC80DE3136EF3923D4D1647738
Firma r         : 85684707A3101EC14121D1EDF28BB7A7CC7AE119CD39D7136984A2E0B2A6E1A1
Firma s         : C7E6E690AE1C1062F62F56565738CABA727EC0788E38E388B5D7FA193804634A
```

Una segunda ejecución con los mismos argumentos produce **exactamente** la misma (r, s): comportamiento esperado con RFC 6979.

**3) Verificación con la clave pública**

```text
$ ./build/ecdsa_cli verify FB7B...5895 BFF5...2911 8568...E1A1 C7E6...634A ExamenFinal
[VALIDA] La firma digital es AUTENTICA e INTEGRA para el mensaje "ExamenFinal".
```

**4) Rechazo de entrada inválida**

```text
$ ./build/ecdsa_cli sign 0xZZ hola
Error: Clave privada hexadecimal invalida.
```
---

## 7. Pruebas de seguridad (resultados negativos esperados)

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

## 8. Hallazgos relevantes durante las pruebas

1. **Bug en el inverso modular (fase previa).** La implementación binaria devolvía un inverso falso con módulo par y podía entrar en bucle infinito con entradas no coprimas (3 mod 9). Se corrigió con guardas de módulo impar y de u/v nulos.
2. **`cswap` con tamaño incorrecto.** El fragmento de referencia intercambiaba 8 words (256 bits) mientras `BigInt` usa 20 (640 bits): habría corrompido las coordenadas altas. La versión final usa `BIGINT_WORDS`, `len` e `is_infinity`.
3. **RFC 6979 sin `bits2octets`.** El tutorial pasaba el hash sin reducir mód n; se corrigió con `int2octets(bits2int(H(m)) mod n)`. Los dos vectores oficiales de P-256/SHA-256 coinciden exactamente.
4. **Comparación de vectores con ceros a la izquierda.** El vector "test" tiene s = `019F41…`; `bigint_to_hex` omite el cero inicial, por lo que la comparación inicial falló. Se corrigió comparando como `BigInt` (`bigint_cmp`), no como cadena.
5. **Fermat y módulos compuestos.** `k^(m−2) mod m` solo es válido con m primo; se añadió la comprobación k·res ≡ 1 (mod m), por lo que 2 mod 4 y 3 mod 9 siguen devolviendo error.
6. **Coste de la inversión en escalera.** Aplicar Fermat a todas las operaciones de campo implica ~512 multiplicaciones modulares por inversión y ralentiza cada multiplicación escalar de forma notable; se usa solo para k⁻¹ (secreto) y se mantiene B.2 en el campo. La suite completa con la escalera tarda 2,62 s.
7. **Compilación limpia.** Con `-Wall -Wextra` no se reportan advertencias en ninguno de los módulos.

---

## 9. Conclusión

La implementación reproduce exactamente los vectores oficiales **NIST CAVP** y **RFC 6979** para P-256/SHA-256, supera los KAT de HMAC-SHA256 de RFC 4231, y rechaza todos los escenarios de manipulación y entradas no canónicas probados: **60 de 60 pruebas superadas, 0 fallidas**.

Las mitigaciones de canal lateral son parciales (escalera de Montgomery y `cswap` sin ramas por bit, inversión de k por Fermat) y están documentadas en `Funcionamiento_e_Implementacion.md`, junto con las limitaciones restantes (operaciones de campo con control de flujo variable, ausencia de DER/PEM).