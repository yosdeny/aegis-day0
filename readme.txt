=== Aegis Day0 ===
Contributors: yosdeny
Tags: security, vulnerability scanner, wpscan, firewall, malware
Requires at least: 7.0
Tested up to: 7.1
Requires PHP: 8.0
Tested PHP: 8.2
Stable tag: 0.2
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

= 0.2 =
Actualización crítica de seguridad. Se recomienda actualizar inmediatamente.

== Author ==
YGB
