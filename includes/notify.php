<?php
class Aegis_Day0_Notify {

    public static function alert_admin($plugin, $type, $severity) {
        $admin_email = get_option('admin_email');
        $subject = "⚠️ Aegis Day0 - Vulnerabilidad detectada";
        $message = "Se ha detectado una vulnerabilidad:\n\n";
        $message .= "Plugin: $plugin\n";
        $message .= "Tipo: $type\n";
        $message .= "Severidad: $severity\n";
        $message .= "Fuente: Sistema de escaneo\n\n";
        $message .= "Revise el dashboard de Aegis Day0 para más detalles.";

        wp_mail($admin_email, $subject, $message);
    }
}
