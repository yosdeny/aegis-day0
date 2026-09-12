=== Aegis Day0 ===
Contributors: yosdeny
Tags: security, vulnerability scanner, wpscan, firewall, malware
Requires at least: 7.0
Tested up to: 7.1
Requires PHP: 8.0
Tested PHP: 8.2
Stable tag: 1.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Plugin de seguridad avanzado para WordPress que detecta vulnerabilidades día 0 mediante análisis estático de código e integración con WPScan.

== Description ==

**Aegis Day0** es un plugin de seguridad profesional diseñado para proteger tu sitio WordPress identificando vulnerabilidades críticas en plugins instalados antes de que sean explotadas.

El plugin combina múltiples capas de protección:
* **Análisis estático de código**: Detecta patrones inseguros como inyecciones SQL (SQLi), Cross-Site Scripting (XSS), uso de `eval()`, `unserialize()` y otras funciones peligrosas.
* **Integración con WPScan**: Consulta la base de datos de vulnerabilidades conocidas para identificar riesgos confirmados.
* **Dashboard interactivo**: Interfaz visual con tabla de vulnerabilidades clasificadas por severidad (Crítica, Alta, Media, Baja) con indicadores de color.
* **Sistema de alertas**: Notificaciones inmediatas en el panel de administración y vía correo electrónico.
* **Respuesta automática**: Capacidad de desactivar automáticamente plugins con vulnerabilidades críticas.
* **Registro completo de auditoría**: Logs detallados que incluyen fecha, plugin afectado, tipo de vulnerabilidad, severidad, fuente de detección y acciones tomadas.
* **Exportación flexible**: Descarga de registros en formatos CSV y JSON para análisis externo.
* **Reportes programados**: Envío automático de informes con frecuencia configurable (diario, semanal, mensual) a múltiples destinatarios.

== Installation ==

1. Sube la carpeta `aegis-day0` al directorio `/wp-content/plugins/`.
2. Activa el plugin desde el menú "Plugins" en el panel de administración de WordPress.
3. Accede a la configuración en el nuevo menú **Aegis Day0**.

== Frequently Asked Questions ==

= ¿Requiere configuración adicional? =
No, el plugin funciona inmediatamente tras la activación. Sin embargo, se recomienda configurar los destinatarios de reportes y revisar las opciones de auto-desactivación según tus necesidades.

= ¿Afecta el rendimiento del sitio? =
El escaneo se ejecuta bajo demanda o programadamente en segundo plano, sin impactar el rendimiento frontal del sitio web.

= ¿Cómo manejo los falsos positivos? =
Los resultados del análisis estático deben ser verificados manualmente. El plugin proporciona el contexto exacto del código detectado para facilitar la validación.

== Screenshots ==

1. Dashboard principal con resumen de vulnerabilidades y severidad.
2. Tabla detallada de resultados del escaneo.
3. Configuración de reportes programados y notificaciones.

== Changelog ==

= 1.0 =
* **Lanzamiento de la versión estable 1.0**: Primera versión oficial del plugin.
* **Sistema avanzado de gestión de falsos positivos**: Implementación de un sistema robusto para marcar, almacenar y filtrar alertas como falsos positivos con persistencia en base de datos.
* **Snapshot inteligente de estado**: Algoritmo de comparación de logs que detecta automáticamente nuevas incidencias comparando el estado actual con el último escaneo válido, evitando revisiones innecesarias cuando no hay cambios.
* **Garantía de integridad de datos**: Todas las alertas generadas incluyen ahora explícitamente la ruta del archivo (`file_path`) normalizada, asegurando consistencia en la generación de hashes y el filtrado de falsos positivos.
* **Soporte completo para todos los niveles de severidad**: Corrección de errores que impedían guardar falsos positivos en alertas de nivel Low y Medium. Ahora el sistema maneja correctamente Critical, High, Medium y Low.
* **Normalización de rutas multiplataforma**: Las rutas de archivos se normalizan automáticamente (slashes, prefijos) para garantizar compatibilidad entre Windows y Linux.
* **Optimización de almacenamiento**: Los snapshots de estado ahora guardan únicamente hashes esenciales, reduciendo drásticamente el uso de base de datos y eliminando errores de serialización.
* **Interfaz mejorada de gestión**: Botón de Acciones funcional que permite revisar archivos específicos o marcar plugins completos como falsos positivos usando comodines.
* **Limpieza automática en desinstalación**: El script `uninstall.php` elimina completamente todas las opciones, transients y tablas relacionadas, incluyendo los nuevos logs de snapshots.
* Mejora en detección de falsos positivos: El analizador AST reconoce automáticamente patrones seguros de inclusión de archivos usando constantes estándar de WordPress.
* Corrección de estilos CSS en el dashboard: tabla de vulnerabilidades ahora se muestra correctamente estructurada.

= 0.4 =
* Nueva funcionalidad en el dashboard: botón "Limpiar Alertas y Re-escanear" que elimina todos los resultados almacenados previamente y ejecuta un escaneo completamente limpio desde cero.
* Interfaz visual para gestionar falsos positivos: ahora puedes limpiar manualmente el historial de alertas y forzar un re-escaneo con las reglas actualizadas directamente desde el dashboard.
* Mejora en detección de falsos positivos: El analizador AST ahora reconoce automáticamente patrones seguros de inclusión de archivos usando constantes estándar de WordPress (__DIR__, __FILE__, ABSPATH, WP_PLUGIN_DIR, etc.) y constantes personalizadas que siguen convenciones de nomenclatura seguras.
* Reducción significativa de alertas innecesarias por "inclusión dinámica" cuando la ruta está construida con constantes seguras.
* Corrección de estilos CSS en el dashboard: tabla de vulnerabilidades ahora se muestra correctamente estructurada con columnas alineadas y diseño responsive.
* Optimización del sistema de reporte para identificar con mayor precisión vulnerabilidades reales.

= 0.3 =
* Mejora en detección de falsos positivos: El analizador AST ahora reconoce automáticamente patrones seguros de inclusión de archivos usando constantes estándar de WordPress (__DIR__, __FILE__, ABSPATH, WP_PLUGIN_DIR, etc.) y constantes personalizadas que siguen convenciones de nomenclatura seguras.
* Reducción significativa de alertas innecesarias por "inclusión dinámica" cuando la ruta está construida con constantes seguras.
* Corrección de estilos CSS en el dashboard: tabla de vulnerabilidades ahora se muestra correctamente estructurada con columnas alineadas y diseño responsive.
* Optimización del sistema de reporte para identificar con mayor precisión vulnerabilidades reales.

= 0.2 =
* Mejoras de seguridad: implementación de nonces CSRF, escape de salida y sanitización de entradas.
* Token de API ahora se almacena de forma segura en las opciones de WordPress.
* Validación mejorada de respuestas HTTP y rutas de archivos.
* Actualización de metadata del plugin.

= 0.1 =
* Lanzamiento inicial.
* Análisis estático de código.
* Integración básica con WPScan.
* Sistema de logs y exportación.

== Upgrade Notice ==

= 1.0 =
Lanzamiento de la versión estable 1.0. Incluye sistema completo de gestión de falsos positivos, snapshot inteligente de estado, garantía de integridad de datos en alertas, soporte para todos los niveles de severidad y optimización de almacenamiento. Actualización recomendada para todos los usuarios.

= 0.4 =
Nueva función para limpiar falsos positivos: botón en el dashboard para eliminar alertas almacenadas y re-escanear desde cero. Mejoras en detección de inclusiones dinámicas seguras.

= 0.3 =
Mejora importante en la precisión del escáner: reducción de falsos positivos en detección de inclusiones dinámicas y corrección de estilos en el dashboard.

= 0.2 =
Actualización crítica de seguridad. Se recomienda actualizar inmediatamente.

== Author ==
YGB
