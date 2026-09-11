<?php
class Aegis_Day0_Notify {

    /**
     * Almacena las alertas acumuladas para enviar en un solo reporte
     */
    private static $pending_alerts = [];

    /**
     * Inicializa el sistema de notificaciones para acumular alertas
     */
    public static function init_batch_notifications() {
        self::$pending_alerts = [];
    }

    /**
     * Agrega una alerta a la cola de notificaciones pendientes
     * 
     * @param string $plugin Nombre del plugin
     * @param string $type Tipo de vulnerabilidad
     * @param string $severity Severidad
     */
    public static function queue_alert($plugin, $type, $severity) {
        $key = md5($plugin . '|' . $type . '|' . $severity);
        
        if (!isset(self::$pending_alerts[$key])) {
            self::$pending_alerts[$key] = [
                'plugin' => sanitize_text_field($plugin),
                'type' => sanitize_text_field($type),
                'severity' => sanitize_text_field($severity),
                'count' => 1
            ];
        } else {
            self::$pending_alerts[$key]['count']++;
        }
    }

    /**
     * Envía un único reporte consolidado con todas las alertas detectadas
     * 
     * @return bool True si se envió el correo, false si no hay alertas o falla el envío
     */
    public static function send_batch_report() {
        if (empty(self::$pending_alerts)) {
            return false;
        }

        $admin_email = get_option('admin_email');
        
        // Validate email address
        if (!is_email($admin_email)) {
            self::$pending_alerts = [];
            return false;
        }

        // Organizar alertas por severidad
        $organized = [
            'Critical' => [],
            'High' => [],
            'Medium' => [],
            'Low' => []
        ];

        foreach (self::$pending_alerts as $alert) {
            $severity = $alert['severity'];
            if (isset($organized[$severity])) {
                $organized[$severity][] = $alert;
            }
        }

        // Construir el mensaje
        $subject = sprintf(__('⚠️ Aegis Day0 - %d vulnerabilidades detectadas', 'aegis-day0'), count(self::$pending_alerts));
        
        $message = __("=== REPORTE DE SEGURIDAD AEGIS DAY0 ===\n\n", 'aegis-day0');
        $message .= sprintf(__("Se han detectado %d vulnerabilidades en total:\n\n", 'aegis-day0'), count(self::$pending_alerts));

        // Sección Critical
        if (!empty($organized['Critical'])) {
            $message .= __("🔴 CRÍTICAS (" . count($organized['Critical']) . "):\n", 'aegis-day0');
            foreach ($organized['Critical'] as $alert) {
                $count_info = $alert['count'] > 1 ? " ({$alert['count']} veces)" : "";
                $message .= sprintf(
                    __("  • Plugin: %s | Tipo: %s%s\n", 'aegis-day0'),
                    $alert['plugin'],
                    $alert['type'],
                    $count_info
                );
            }
            $message .= "\n";
        }

        // Sección High
        if (!empty($organized['High'])) {
            $message .= __("🟠 ALTAS (" . count($organized['High']) . "):\n", 'aegis-day0');
            foreach ($organized['High'] as $alert) {
                $count_info = $alert['count'] > 1 ? " ({$alert['count']} veces)" : "";
                $message .= sprintf(
                    __("  • Plugin: %s | Tipo: %s%s\n", 'aegis-day0'),
                    $alert['plugin'],
                    $alert['type'],
                    $count_info
                );
            }
            $message .= "\n";
        }

        // Sección Medium
        if (!empty($organized['Medium'])) {
            $message .= __("🟡 MEDIAS (" . count($organized['Medium']) . "):\n", 'aegis-day0');
            foreach ($organized['Medium'] as $alert) {
                $count_info = $alert['count'] > 1 ? " ({$alert['count']} veces)" : "";
                $message .= sprintf(
                    __("  • Plugin: %s | Tipo: %s%s\n", 'aegis-day0'),
                    $alert['plugin'],
                    $alert['type'],
                    $count_info
                );
            }
            $message .= "\n";
        }

        // Sección Low
        if (!empty($organized['Low'])) {
            $message .= __("🟢 BAJAS (" . count($organized['Low']) . "):\n", 'aegis-day0');
            foreach ($organized['Low'] as $alert) {
                $count_info = $alert['count'] > 1 ? " ({$alert['count']} veces)" : "";
                $message .= sprintf(
                    __("  • Plugin: %s | Tipo: %s%s\n", 'aegis-day0'),
                    $alert['plugin'],
                    $alert['type'],
                    $count_info
                );
            }
            $message .= "\n";
        }

        $message .= __("=== FIN DEL REPORTE ===\n\n", 'aegis-day0');
        $message .= __("Revise el dashboard de Aegis Day0 para más detalles y acciones recomendadas.", 'aegis-day0');

        $headers = ['Content-Type: text/plain; charset=UTF-8'];
        
        $result = wp_mail(sanitize_email($admin_email), $subject, $message, $headers);
        
        // Limpiar alertas pendientes después de enviar
        self::$pending_alerts = [];
        
        return $result;
    }

    /**
     * Método legacy para compatibilidad - ahora enqueue la alerta en lugar de enviar inmediatamente
     * 
     * @deprecated Usar queue_alert() + send_batch_report() en su lugar
     * @param string $plugin Nombre del plugin
     * @param string $type Tipo de vulnerabilidad
     * @param string $severity Severidad
     */
    public static function alert_admin($plugin, $type, $severity) {
        self::queue_alert($plugin, $type, $severity);
    }
}
