# Análisis de Escalamiento y ROI: OsintUltimate Bug Bounty
> **Perfil de Usuario:** Bug Hunter (Híbrido Oracle/DO) · **Versión:** 1.1

---

## 1. Matriz de Costos por Volumen (Mensual vs Anual)
Cálculo basado en Digital Ocean (Droplets de 2vCPU/2GB para escaneo complejo de ~2 horas por target).

| Targets/Día | Droplets Simultáneos | Costo Mensual VPS | Costo Anual VPS | Observaciones |
|---|---|---|---|---|
| **5 Targets** | 1 (Escalable) | **~$6.00** | **$72.00** | 1 Droplet "Basic" de $6 es suficiente si es secuencial. |
| **15 Targets** | 1-2 (Paralelo) | **~$15.00** | **$180.00** | Requiere Droplet "Premium" o 2 Básicos para no colapsar. |
| **30 Targets** | 3 (Paralelo) | **~$36.00** | **$432.00** | Capacidad máxima de paralelismo para cobertura amplia. |

---

## 2. Gestión de Activos y Créditos (Sostenibilidad Anual)

### 2.1 — APIs de IA ($40/mes + Créditos)
*   **Claude/Kimi ($40/mes):** Con el enrutamiento de V14.8, estos $40 deben durar el mes completo.
*   **Azure Student ($100):** 
    *   **Estrategia:** Dividir en **$8.33/mes**. 
    *   **Uso:** Solo como "Failover Tier 3" cuando Claude/Kimi alcancen el 90% de su cuota diaria. 
    *   **Resultado:** Alcanzarás el año entero con saldo positivo.

### 2.2 — "Tanque de Combustible" (Créditos No Recurrentes)
*   **Shodan ($50 student) + Netlas ($40):** 
    *   A 30 targets/día, estos $90 en créditos de recon durarán aproximadamente **4-6 meses** si se usan solo para filtros específicos (no escaneos masivos de rangos).
    *   **Chaos/CriminalIP/SecurityTrails (Gratis):** Son la fuente primaria de datos para ahorrar los créditos anteriores.

---

## 3. Análisis de Rentabilidad (ROI Bug Bounty)

### Gastos Fijos (Infraestructura + IA)
*   **Costo Mensual Tier 30 targets:** **~$85.00** (VPS + IA + Software Pro).
*   **Costo Anual Tier 30 targets:** **~$1,020.00**.

### Proyección de Ganancias (Estimación Conservadora)
| Evento | Frecuencia Est. | Valor Bounties | ROI Bruto |
|---|---|---|---|
| **Bounties Bajos (P4)** | 2-3 por mes | $150 | Cubre gastos mensuales y sobra $65. |
| **Bounties Medios (P3)** | 1 cada 3 meses | $300 - $500 | Paga medio año de infraestructura. |
| **Bounty Alto (P1/P2)** | 1 al año | $1,500 - $5,000 | **Paga entre 1.5 y 5 años de operación.** |

---

## 4. ¿Te alcanzará para ganancias extras?
**SÍ.** Con 30 targets diarios complejos, estarás escaneando **900 objetivos al mes**. Estadísticamente, en 900 escaneos profundos (con las capacidades de V14.8), la probabilidad de encontrar al menos **1 vulnerabilidad High o 2-3 Low** es extremadamente alta.

### Puntos a Favor:
1.  **Cero costo de IA local:** Oracle corre Ollama gratis (ahorro de ~$50/mes en GPU/RAM).
2.  **API Student Multiplier:** Tus APIs de Shodan/Caido reducen tus gastos operativos iniciales a casi la mitad de lo que pagaría una empresa.
3.  **Foco en Calidad:** La sanitización de tokens (V14.8) hace que tu presupuesto de $20 rinda como si tuvieras $100.

---

## 5. Recomendación Técnica para Maximizr Ganancia Anual
1.  **Usa `osint_route_task` disciplinadamente.** No dejes que tareas triviales ("¿qué es este puerto?") consuman tu crédito de Claude.
2.  **Azure Failover Automático.** Configura el core para que cuando el API de Claude retorne 429 (Rate Limit), use Azure Student hasta el día siguiente.
3.  **Digital Ocean On-Demand.** No tengasDroplets encendidos si no hay tareas. Usa el comando `doctl` (o el plugin que desarrollaremos) para apagar los nodos de escaneo en las horas de inactividad.

_Análisis de Viabilidad Bug Bounty — OsintUltimate V1.1_
