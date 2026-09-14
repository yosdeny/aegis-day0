=== Aegis Day0 ===
Contributors: yosdeny
Tags: security, vulnerability scanner, wpscan, firewall, malware
Requires at least: 7.0
Tested up to: 7.1
Requires PHP: 8.0
Tested PHP: 8.2
Stable tag: 0.4
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Escáner de seguridad proactivo para WordPress que detecta vulnerabilidades Day0, inyecciones SQL, XSS y configuraciones inseguras directamente desde el dashboard.

== Description ==

Aegis Day0 Security Scanner es una herramienta avanzada diseñada para desarrolladores y administradores de WordPress que necesitan auditar la seguridad de sus plugins y temas. A diferencia de los escáneres tradicionales, Aegis utiliza análisis estático profundo, análisis de tokens y AST (Abstract Syntax Tree) para encontrar vulnerabilidades complejas que otros pasan por alto.

**Características Principales:**

*   **Detección de Inyección SQL:** Identifica usos incorrectos de `$wpdb->prepare()`, consultas dinámicas y marcadores desbalanceados.
*   **Detección de XSS:** Encuentra ecos de variables no sanitizadas (`$_GET`, `$_POST`, `$_REQUEST`) sin funciones de escape apropiadas.
*   **Inclusión de Archivos Dinámicos:** Detecta `include`, `require`, `include_once` y `require_once` con variables dinámicas.
*   **Análisis de AJAX y Nonces:** Revisa endpoints AJAX para asegurar la validación de nonces y capacidades.
*   **Visualización de Contexto de Código:** Muestra fragmentos de código exactos (línea del error + contexto) para TODOS los tipos de vulnerabilidades, facilitando la corrección inmediata sin abrir archivos.
*   **Gestión de Falsos Positivos:** Permite marcar alertas como falsos positivos para limpiar el dashboard.
*   **Optimizado para Grandes Plugins:** Escaneo recursivo eficiente capaz de manejar cientos de archivos sin saturar la memoria.

== Installation ==

1.  Sube la carpeta `aegis-day0` al directorio `/wp-content/plugins/`.
2.  Activa el plugin a través de la sección 'Plugins' en WordPress.
3.  Ve a `Aegis Day0` en el menú lateral para iniciar tu primer escaneo.

== Frequently Asked Questions ==

= ¿Este plugin ralentiza mi sitio? =
No. El escaneo se ejecuta bajo demanda cuando un administrador inicia el proceso desde el dashboard. No afecta al rendimiento frontal del sitio.

= ¿Qué hago si detecta un falso positivo? =
Puedes hacer clic en el botón "Marcar como FP" junto a la alerta. El sistema recordará esta decisión para futuros escaneos.

= ¿Funciona con plugins personalizados? =
Sí, escanea cualquier archivo PHP dentro de la instalación de WordPress, incluyendo plugins personalizados, temas y mu-plugins.

== Changelog ==

= 1.2.0 =
*   **MEJORA CRÍTICA:** Visualización de fragmentos de código para TODOS los errores detectados (SQL Injection, XSS, File Inclusion, Eval usage, AJAX insecurity, etc.). El dashboard ahora muestra 2 líneas antes y después del error, con la línea problemática resaltada en rojo y una flecha indicadora.
*   **MEJORA:** Reporte detallado para errores de `$wpdb->prepare()` mostrando ruta relativa exacta, número de línea, conteo de marcadores (%s, %d, %f) vs argumentos pasados, y vista previa de la consulta SQL.
*   **OPTIMIZACIÓN:** Escaneo recursivo eficiente para plugins con cientos de archivos sin saturar la memoria.
*   **FIX:** Corregido error fatal "Cannot redeclare __construct()" en class-ast-analyzer.php.
*   **FIX:** Corregido error fatal "Call to undefined method get_current_content()" en análisis AST.
*   **FIX:** Restaurados botones de "Marcar como FP" (Falso Positivo) en el dashboard.
*   **UX:** Mejora drástica en la usabilidad para identificar y corregir vulnerabilidades sin abrir archivos manualmente.

= 0.4 =
*   Lanzamiento inicial con capacidades básicas de escaneo.
*   Detección de vulnerabilidades SQL y XSS.
*   Interfaz de dashboard básica.

= 0.3 =
*   Mejoras en el análisis de tokens.
*   Corrección de bugs menores.

= 0.2 =
*   Añadir soporte para análisis de archivos de temas.

= 0.1 =
*   Versión inicial.

== Upgrade Notice ==

= 1.2.0 =
Actualización crítica de usabilidad. Ahora verás el código exacto donde ocurren los errores para facilitar la corrección. Se han resuelto errores fatales en el análisis AST.
