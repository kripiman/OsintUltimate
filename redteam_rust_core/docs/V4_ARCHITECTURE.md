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

## 5. Sandboxing Híbrido & Hardware Tiering (Vector 5)

OsintUltimate v4.0 introduce un sistema de ejecución adaptativo basado en el perfil de hardware del anfitrión.

### SysResourceManager
Utiliza la crate `sysinfo` para monitorear en tiempo real la RAM y Swap disponibles.
- **Pre-flight Check**: Antes de lanzar cualquier herramienta, el sistema calcula el costo estimado (Ligero/Medio/Pesado) y verifica si hay memoria disponible para evitar bloqueos del SO (OOM).

### SandboxDispatcher: Dos Niveles de Aislamiento
El motor selecciona la estrategia de ejecución dinámicamente:
1. **Strict Tier (Sistemas >= 16GB RAM)**: Aislamiento total mediante contenedores **Docker efímeros**. Se inyectan límites de memoria estrictos (`--memory`) para cada contenedor.
2. **Fluid Tier (Sistemas < 16GB RAM)**: Ejecución nativa optimizada. Utiliza **ProcessGuard (PGID)** para aislar grupos de procesos y garantizar la limpieza de procesos hijos sin el overhead de Docker.

### La Regla de Excepción de Explotación
Independientemente del tier de RAM, cualquier herramienta catalogada como **"Exploitation"** (ej. SqlMap, exploits de PoC) se fuerza a ejecutarse en el **Strict Tier (Docker)**. Esto garantiza que el código potencialmente peligroso o inestable nunca toque el sistema operativo anfitrión de forma nativa.

---

## 6. Command Center Dashboard v2.0 (Vector 6)

El Dashboard v2.0 trasciende la monitorización básica para convertirse en una interfaz de control operativa táctiva para el Red Team.

### Attack Correlation Graph (D3.js)
- **Visualización**: Renderizado en tiempo real de nodos (objetivos y hallazgos) y sus aristas de correlación.
- **Interactividad**: Permite identificar de un vistazo las cadenas de ataque (attack chains) mediante la proximidad física de los nodos en el grafo de simulación de fuerzas.
- **Grafo de Gravedad**: El tamaño de los nodos escala según la severidad del hallazgo, permitiendo priorizar la atención humana en activos críticos.

### Swarm Monitoring & Human-in-the-Loop
- **Estado de Agentes**: Panel en vivo que muestra la actividad detallada de los 4 roles (Planner, Scout, Exploiter, Reporter).
- **Approval Gate Interactiva**: Integración nativa con el sistema de autorizaciones. Cuando un agente (`Exploiter`) requiere permiso para lanzar una acción de alto riesgo, el Dashboard dispara un modal de decisión que pausa el flujo hasta la intervención humana.
- **Token Budget Gauge**: Monitoreo visual del consumo de cuotas de IA (Gemini/Claude/OpenAI) para evitar sobrecostos accidentales.

## 7. Source-Aware Correlation (Vector 7)

Introducción del análisis de código fuente nativo para una cobertura de seguridad 360°.

### Local Lightweight SAST
- **Extracción de Endpoints**: El motor analiza automáticamente archivos de rutas (Express, Flask, Django) para mapear la superficie de ataque sin necesidad de fuzzing exhaustivo.
- **Identificación de Sinks**: Uso de extractores optimizados para JS/TS y Python que localizan funciones peligrosas (`eval`, `os.system`, `subprocess`) y las marcan como objetivos de alta prioridad.
- **Context-Aware Token Optimization**: Sistema de compresión que envía solo fragmentos de código relevantes y abstrae la lógica, minimizando el consumo de tokens en modelos premium.

### SAST-DAST Correlation Loop
- **Vínculos de Confianza**: Si un hallazgo dinámico (DAST) coincide con un endpoint o sink identificado en el código (SAST), el motor eleva automáticamente la confianza al 100% y genera un PoC especializado basado en la lógica del código fuente.
- **Git Integration**: Capacidad nativa para clonar repositorios remotos y realizar análisis "on-the-fly" durante la fase de reconocimiento.
+
+## 8. Planeación Determinista (ARCH-03)
+
+Para maximizar la eficiencia y confiabilidad, la clasificación de objetivos (Network vs Web App) y el enrutamiento inicial entre los agentes `Scout` y `Exploiter` se ha migrado a un modelo **determínistico basado en reglas**.
+
+### ¿Por qué?
+El uso de LLMs para decisiones binarias de enrutamiento introducía latencia innecesaria y riesgos de alucinación en la fase crítica de descubrimiento.
+
+### Detalles de Implementación:
+- **Capa de Clasificación**: Los resultados de escaneo de puertos alimentan un `TargetClassifier` que utiliza firmas estáticas (ej. detección de HTTP/S, SSH, SMB).
+- **Enrutamiento**: El `Planner` utiliza la salida del clasificador para asignar tareas de forma instantánea, reservando el presupuesto de tokens de la IA para el análisis profundo de vulnerabilidades y la mutación de payloads.
+

---

© 2026 RedTeam Lab | OsintUltimate v4.0 Documentation
