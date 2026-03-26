# Arquitectura y Plan de Integración: Herramientas BlackArch para IA en OsintUltimate

## Visión General
Este documento establece la hoja de ruta y los pilares arquitectónicos para integrar las capacidades completas (más de 2800 herramientas) de **BlackArch Linux** dentro de `OsintUltimate`. El objetivo es permitir que la IA orqueste de manera autónoma procesos de OSINT, escaneo, movimiento lateral, explotación y evasión, **manteniendo un rendimiento optimizado, bajo consumo de recursos y alta eficacia**.

---

## 1. Diseño de Arquitectura Eficiente

Para evitar sistemas pesados y tiempos de carga ineficientes, la integración no debe depender de instalar todo el ecosistema BlackArch localmente de inicio.

### A. Estrategia de Herramientas bajo Demanda (Tools-on-Demand)
*   **Core Set Pre-instalado:** El contenedor principal (`Dockerfile`) instalará únicamente un conjunto mínimo de herramientas esenciales (ej. `nmap`, utilidades de red base, entorno de terminal aislado).
*   **Aprovisionamiento Dinámico:** Si la IA decide que necesita una herramienta específica de BlackArch (ej. `sqlmap`, `metasploit`, scripts de evasión), un gestor interno invocará `pacman` silenciosamente para instalarla en tiempo real en un entorno efímero o layer del contenedor. Una vez terminada la fase de ataque, la herramienta puede cachearse o desecharse según la memoria disponible.

### B. Módulo de Ejecución Creado en Rust (`tool_executor.rs`)
*   Se extenderá el `redteam_rust_core` para incluir un motor asíncrono basado en `tokio::process`.
*   **Aislamiento:** Las herramientas más sensibles (exploits) se ejecutarán usando namespaces de Linux o `chroot` para evitar comprometer la plataforma base (sandboxing).

---

## 2. Interacción entre la IA (LLM) y BlackArch

La IA no interactuará con la terminal a ciegas; lo hará mediante una abstracción segura para evitar errores de sintaxis y daños accidentales.

### A. Descripciones Funcionales (Tool Manifests)
Para cada herramienta o categoría de herramientas soportada, se inyectarán "Manifests" en el contexto de la IA (`ai_cascade.rs`), que incluyen:
1.  **Comando base y parámetros permitidos.**
2.  **Contexto técnico:** Para qué sirve y cuándo usarse (Evasión, OSINT, etc.).
3.  **Restricciones:** Ej. "No usar escaneos ruidosos si se requiere evasión".

### B. Parsers de Salida y Filtros Inteligentes
Uno de los mayores cuellos de botella para una IA es ingerir logs crudos gigantes (ej. salidas masivas de escaneos de vulnerabilidades).
*   **Traducción de Datos:** Se escribirán parsers en Rust que tomen el *stdout* de las herramientas BlackArch y lo conviertan a un JSON resumido.
*   **Filtrado Heurístico:** Antes de enviar el resultado a la IA, el sistema descartará los falsos positivos y la "basura" (ej. puertos ruidosos, subdominios caídos) ahorrando tokens de inferencia y tiempo (optimizando la calidad sin perder contexto).

---

## 3. Optimización de Rendimiento y Recursos

Continuando con la gestión consciente del hardware (Hardware-Aware Resource Management):

*   **Paginación y Streaming Batch:** Si una herramienta devuelve flujos continuos de datos, Rust los agrupará en lotes (batches) comprimidos usando la infraestructura existente, enviándolos a la IA por partes.
*   **Control de Concurrencia Limitado:** Herramientas que exijan alta CPU/Red serán encoladas o sus hilos de ejecución reducidos drásticamente basándose en el módulo de detección de memoria (operable incluso con 1GB de RAM).
*   **Timeouts Estrictos:** Cada ejecución ordenanda por la IA tendrá un `timeout` agresivo para evitar que un proceso colgado sature el sistema.

---

## 4. OPSEC, Privacidad y Evasión

*   **Auto-Evasión Orquestada:** La IA estará programada para anteceder sus comandos con herramientas de ofuscación de red y capas de proxy (ej. `proxychains-ng`, `tor`) nativas en el propio BlackArch.
*   **Limpieza de Pistas:** Las herramientas de post-explotación estarán envueltas por un proceso que limpia logs y temporales localmente dentro de los objetivos.
*   **SecretScrubber Activo:** Todas las salidas recolectadas pasarán por la limpieza local (sanitización) para no exponer credenciales o IPs sensibles a IAs externas.

---

## 5. Próximos Pasos (Roadmap de Ejecución)

1.  [ ] **Actualizar Infraestructura:** Modificar la imagen base de Docker a Arch Linux/BlackArch (`blackarch/blackarch-bare`).
2.  [ ] **Desarrollo del Executor:** Crear `src/core/blackarch_bridge.rs` para permitir las peticiones de línea de comandos asíncronas desde la IA.
3.  [ ] **Mapeo de Herramientas Inicial:** Configurar los primeros 5 "Tool Manifests" dedicados a OSINT puro.
4.  [ ] **Pruebas de Estrés:** Medir el rendimiento en contenedores restringidos (<2GB RAM) corriendo cadenas de llamadas IA -> Herramienta BlackArch -> IA.
