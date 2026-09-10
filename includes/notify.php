<?php
class Aegis_Day0_Notify {

    public static function alert_admin($plugin, $type, $severity) {
        // Sanitize inputs
        $plugin   = sanitize_text_field($plugin);
        $type     = sanitize_text_field($type);
        $severity = sanitize_text_field($severity);
        
        $admin_email = get_option('admin_email');
        
        // Validate email address
        if (!is_email($admin_email)) {
            return;
        }
        
        $subject = __('⚠️ Aegis Day0 - Vulnerabilidad detectada', 'aegis-day0');
        $message = sprintf(
            __("Se ha detectado una vulnerabilidad:\n\nPlugin: %s\nTipo: %s\nSeveridad: %s\nFuente: Sistema de escaneo\n\nRevise el dashboard de Aegis Day0 para más detalles.", 'aegis-day0'),
            $plugin,
            $type,
            $severity
        );

        $headers = ['Content-Type: text/plain; charset=UTF-8'];
        
        wp_mail(sanitize_email($admin_email), $subject, $message, $headers);
    }
}
