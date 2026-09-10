========================================
🛡️ Aegis Day0 - Plugin de Seguridad
========================================

Descripción:
------------
Aegis Day0 es un plugin de seguridad para WordPress diseñado para detectar 
vulnerabilidades día 0 en otros plugins instalados. Combina análisis estático 
de código, integración con WPScan y un sistema de alertas en tiempo real.

Características:
----------------
- Escaneo estático de patrones inseguros (SQLi, XSS, eval, unserialize).
- Integración con WPScan para vulnerabilidades conocidas.
- Dashboard visual con tabla de vulnerabilidades y severidad por colores.
- Notificaciones en tiempo real en el admin y por correo.
- Opción de desactivar automáticamente plugins vulnerables críticos.
- Historial de logs detallados con fecha, plugin, tipo, severidad, fuente y acción.
- Exportación de logs en CSV y JSON.
- Reportes programados con frecuencia configurable (diario, semanal, mensual).
- Selector de hora de envío y destinatarios de reportes.
- Acceso restringido exclusivamente a administradores.

Instalación:
------------
1. Copiar la carpeta `aegis-day0` en `wp-content/plugins/`.
2. Activar el plugin desde el panel de administración de WordPress.
3. Configurar opciones en el menú **Aegis Day0**.

Configuración:
--------------
- Auto-desactivación: Checkbox para habilitar o no la desactivación automática.
- Frecuencia de reportes: Diario, Semanal o Mensual.
- Hora de envío: Campo para definir la hora exacta del reporte.
- Destinatarios: Correos separados por coma. Si está vacío, se usa el admin_email.

Seguridad:
----------
- Solo administradores pueden acceder al dashboard y configurar opciones.
- Todas las acciones quedan registradas en los logs para auditoría.

Buenas prácticas:
-----------------
- Revisar el dashboard periódicamente.
- Exportar los logs para análisis externo.
- Mantener WordPress y plugins actualizados.
- Configurar reportes programados para el equipo de seguridad.

Autor:
------
Yosdeny

Versión:
--------
0.1
