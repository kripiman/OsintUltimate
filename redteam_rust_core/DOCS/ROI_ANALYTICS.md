# 📊 Mimikri ROI Analytics: Priorización Basada en Datos

Mimikri utiliza un marco de trabajo de Selección de Objetivos (Stage -1) diseñado para maximizar el retorno de inversión (ROI) del tiempo del operador y los recursos computacionales.

## 1. El Motor de Scoring ROI

El `ProgramAnalyzer` utiliza una fórmula determinista para puntuar cada programa de Bug Bounty. La puntuación es dinámica y se recalibra periódicamente mediante telemetría real.

### Fórmula Matemática
$$ROI = \frac{MedianPayout \times SuccessRate \times ProvenBonus}{AgeFactor \times Difficulty}$$

| Componente | Descripción | Fuente de Datos |
| :--- | :--- | :--- |
| **Median Payout** | Pago promedio por vulnerabilidad (USD). | Plataforma (H1/BC) |
| **Success Rate** | Probabilidad de que un reporte sea aceptado. | Telemetría (Fase 0) |
| **Proven Bonus** | Multiplicador para programas "gemas ocultas" o "hot fresh". | `calculate_proven_bonus` |
| **Age Factor** | Penalización por saturación de programas antiguos. | `get_age_factor` |
| **Difficulty** | Multiplicador basado en la complejidad de la superficie. | `ScopeDifficulty` |

---

## 2. Rúbricas Numéricas

### Multiplicadores de Dificultad (`ScopeDifficulty`)
- **Single TLD (1.0x)**: Un solo dominio, superficie reducida.
- **Wildcard Standard (2.5x)**: Dominios wildcard, aplicaciones web estándar.
- **Massive JS-Heavy (4.0x)**: SPA masivas, microservicios, APIs complejas.
- **Mobile/Hardware (5.0x)**: Objetivos exóticos, IoT, binarios móviles.

### Factor de Antigüedad (`AgeFactor`)
- **< 6 meses (1.0x)**: Alta volatilidad, muchas oportunidades.
- **6 - 24 meses (1.5x)**: Programa estable.
- **> 24 meses (3.0x)**: Saturado, alta competencia.

### Multiplicador de Confianza (`ProvenBonus`)
- **Hot Fresh (1.3x)**: Programa nuevo (< 6 meses) con pocos reportes (< 50).
- **Forgotten Gem (1.5x)**: Programa antiguo (> 24 meses) con pocos reportes (< 50).
- **Default Low-Vol (1.2x)**: Cualquier programa con < 50 reportes resueltos.

---

## 3. Estrategia de Validación (Roadmap)

El sistema de ROI no se integra a ciegas. Sigue un proceso de calibración de dos etapas:

### Fase 0: Recolección de Telemetría (Baseline)
- **Duración**: 2 semanas.
- **Acción**: El sistema funciona en modo pasivo/manual recolectando ratios reales de hallazgos por hora y tasas de rechazo.
- **Objetivo**: Establecer el "ruido de fondo" y calibrar los umbrales del Filtro de Falsos Positivos (FPF).

### Fase 1: Calibración y Ranking
- **Acción**: Uso de `ProgramAnalyzer` para ordenar la cola de trabajo.
- **Objetivo**: Asegurar que los recursos de IA (Premium LLMs) se reserven para los objetivos con mayor probabilidad de pago.

### Fase 2: Test Empírico 50/50
- **Acción**: División de recursos entre selección manual y selección por ROI.
- **Métrica de Éxito**: Mejora de **>1.5x** en $/hora.

---

## 4. Seguridad y Soberanía

Las herramientas de clase APT (Sovereign Tools) están **excluidas** de los perfiles estándar de Bug Bounty mediante gating a nivel de compilación (`#[cfg(feature = "sovereign")]`). Esto garantiza que el sistema de priorización solo sugiera acciones que cumplan con las políticas de los programas públicos.
