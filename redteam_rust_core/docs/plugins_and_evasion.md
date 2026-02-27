# Plugins y Evasión

El sistema está diseñado para ser altamente modular e inyectable, garantizando que añadir nuevas técnicas de auditoría no requiera modificar el core.

## 1. Sistema de Plugins

Existen dos tipos principales de interfaces (`traits`):

*   **`DiscoveryPlugin`**: Módulos que retornan `Vec<String>` (nuevos objetivos encontrados).
*   **`ScannerPlugin`**: Módulos que toman un objetivo y retornan `Vec<Finding>` (vulnerabilidades encontradas).

### Módulos Integrados Clave

*   **OsintScanner**: Integrado nativamente con DNS sobre HTTPS (`hickory-resolver`) y Certificate Transparency (`crt.sh`). Optimizado estructuralmente para evitar bloqueos del resolver local.
*   **WebFuzzer**: Usado para descubrimiento agresivo de configuraciones mal empaquetadas o ficheros por defecto expuestos. Implementa un motor HTTP asíncrono por encima de `reqwest`.
*   **NmapScanner**: Un wrapper dinámico y seguro sobre los binarios binarios Nmap de la máquina host. Compone asincrónicamente los comandos Nmap, redirige el stdout y parsea nativamente los resultados XML, incluyendo de la máquina de scripting de Nmap (`NSE`).

### Plugins Dinámicos (`DynamicPluginLoader`)
OsintUltimate soporta Hot-Reload e inyección de plugins dinámicos. Puedes escribir plugins en Rust, compilarlos como bibliotecas dinámicas (`.so` / `.dylib`), y pasarlas por el parámetro `--plugins-dir`. El loader valida las versiones de C ABI por seguridad antes de ejecutarlos.

---

## 2. Mecanismos de Evasión (Stealth)

Una auditoría no es útil si provoca el bloqueo de los WAF (Web Application Firewalls) o IDS en el primer milisegundo.

*   **Jitter LogNormal**: En el modo `--stealth`, el `WebFuzzer` inyecta demoras pseudo-aleatorias usando una distribución de probabilidad Log-Normal. Este patrón imita matemáticamente las demoras de un ser humano real saltando de un enlace a otro, derrotando a motores heurísticos que vigilan "solicitudes cronometradas a la perfección".
*   **Rotación Inteligente de Proxies (`DashMap`)**: Si se provee una lista con `--proxies`, no es una asignación de proxy trivial; está respaldada por una tabla Hash concurrente en memoria (`DashMap`). El cliente interno rota de manera determinista a través de instancias aisladas, impidiendo bloqueos basados en cuotas de IP de los WAF/Ratelimits.
*   **Fragmentación de Paquetes (`-f`)**: Al lanzar la fase de descubrimiento por Nmap, el engine solicita a bajo nivel a Nmap que ensamble los paquetes SYN troceados para evadir firmas básicas de Firewall L3/L4.
*   **Camuflaje DNS (`DoH`)**: Al resolver las IP internas, es extremadamente ruidoso inundar un servidor DNS corporativo. El flag `--doh` encripta los queries DNS y usa endpoints de confianza, borrando el fingerprinting inicial.
