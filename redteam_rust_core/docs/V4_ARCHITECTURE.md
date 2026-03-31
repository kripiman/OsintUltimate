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
Utilizamos **SimHash (Locality-Sensitive Hashing)** para cachear mutaciones exitosas.
- Si un nuevo payload es similar en un 90% a uno ya mutado con éxito, el sistema reutiliza la mutación instantáneamente.
- **Implementación**: El cache se gestiona en el `WafEvasionEngine` junto con el cliente de IA local (Ollama).

### Tiered Priority Router
Además del LSH y Off-Path, el router de IA v4.0 implementa un sistema de **prioridades deterministas** por nivel:
1. El motor clasifica el hallazgo en un `RouteLevel`.
2. Se intenta el proveedor con mayor prioridad dentro del nivel (ej. Anthropic).
3. En caso de fallo, el sistema realiza un failover transparente al siguiente proveedor en la lista antes de escalar al nivel superior.
4. **Beneficio**: Maximiza el uso de modelos con mejor razonamiento pero menor disponibilidad, manteniendo gpt-4o/Gemini como buffers de confiabilidad.

## 3. Pipeline de Alto Rendimiento (Vector 1)

### Lock-Free Result Sink
Para evitar bloqueos de Mutex en la base de datos (SQLite) bajo alta carga:
- Los resultados se insertan en una `SegQueue` de la crate `crossbeam`.
- Un hilo de ejecución dedicado (`sink-batcher`) extrae los elementos y los escribe en transacciones agrupadas (batches).
- **Resultado**: Cero esperas para los trabajadores de escaneo al reportar hallazgos.

### Native io-uring Scanner
Implementado en `native_scanner.rs`, utiliza la interfaz `io_uring` de Linux para:
- Enviar ráfagas de paquetes SYN de forma asíncrona mediante la SQ (Submission Queue).
- **SQPOLL**: Utiliza hilos de polling del kernel para eliminar el costo de las syscalls `write/send`.
- Requiere privilegios `CAP_NET_RAW` y Kernel 5.1+.

## 4. HashDoS Hardening
Para evitar ataques de denegación de servicio contra los caches internos (especialmente en el `Orchestrator`), hemos migrado a **SipHash-1-3** con llaves aleatorias inicializadas por ejecución.

---

> [!NOTE]
> Esta arquitectura está optimizada para hardware con >= 4 núcleos y kernels modernos. En sistemas antiguos, el motor caerá automáticamente en modos de compatibilidad legados.
