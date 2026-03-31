# 🏗️ Arquitectura OsintUltimate v4.0

La versión 4.0 representa un cambio de paradigma en el motor, pasando de un modelo secuencial a uno **asíncrono puro y probabilístico**.

## 1. Evasión Estocástica (Vector 3)

A diferencia de v3.x, que usaba una escalación determinista (Headers -> TLS -> AI -> IP), v4.0 utiliza **Thompson Sampling**.

### ¿Por qué?
Los WAFs modernos utilizan Machine Learning para identificar patrones de "escalación de herramientas". Una secuencia fija de reintentos es fácil de detectar.

### Implementación
- Cada estrategia tiene un par de valores `(alpha, beta)` que representan una **Distribución Beta**.
- `alpha`: Éxitos (solicitudes no bloqueadas).
- `beta`: Fallos (bloqueos).
- Al recibir un 403, el motor muestrea cada distribución y selecciona la estrategia con el valor más alto.
- **Aprendizaje**: El sistema actualiza los pesos en tiempo real basándose en la efectividad contra el objetivo específico.

## 2. Optimización de IA: Off-Path & LSH (Vector 4)

La inferencia de LLMs es lenta (~100-500ms). En v3.x, esto bloqueaba el hilo de red.

### LSH Payload Cache
Utilizamos **SimHash (Locality-Sensitive Hashing)** para cachear mutaciones.
- Si un payload es similar en un 90% (Distancia de Hamming <= 8) a uno ya mutado con éxito, reutilizamos la mutación instantáneamente.
- Evita llamadas redundantes a LLMs para variaciones de payloads de inyección.

### Off-Path Engine
Si no hay match en el cache:
1. La solicitud de mutación se encola en un `mpsc::channel`.
2. El hilo de red continúa inmediatamente usando una estrategia de fallback (Header Rotation).
3. Un pool de trabajadores analiza el bloqueo y actualiza el cache de LSH en segundo plano.

## 3. Pipeline de Alto Rendimiento (Vector 1)

### Lock-Free Result Sink
Para evitar bloqueos de Mutex en la base de datos (SQLite) bajo alta carga:
- Los resultados se insertan en una `SegQueue` de la crate `crossbeam`.
- Un hilo de ejecución dedicado (`sink-batcher`) extrae los elementos y los escribe en transacciones agrupadas (batches).
- **Resultado**: Cero esperas para los trabajadores de escaneo al reportar hallazgos.

### Native io-uring Scanner
Utiliza la interfaz `io_uring` de Linux para:
- Enviar ráfagas de paquetes SYN sin el overhead de `fork/exec` o múltiples syscalls.
- Soporte para **Zero-Copy** en el envío de paquetes.
- Requiere Kernel 5.1+ y privilegios `CAP_NET_RAW`.

## 4. HashDoS Hardening
Para evitar ataques de denegación de servicio contra los caches internos (especialmente en el `Orchestrator`), hemos migrado a **SipHash-1-3** con llaves aleatorias inicializadas por ejecución.

---

> [!NOTE]
> Esta arquitectura está optimizada para hardware con >= 4 núcleos y kernels modernos. En sistemas antiguos, el motor caerá automáticamente en modos de compatibilidad legados.
