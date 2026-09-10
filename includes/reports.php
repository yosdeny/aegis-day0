<?php
class Aegis_Day0_Reports {

    public static function send_report() {
        $logs = get_option('aegis_day0_logs', []);
        if (empty($logs)) return;

        // Si no hay destinatarios configurados, usar admin_email por defecto
        $recipients = get_option('aegis_day0_report_recipients', '');
        if (empty($recipients)) {
            $recipients = get_option('admin_email');
        }

        $emails = array_map('trim', explode(',', $recipients));

        $subject = "Aegis Day0 - Reporte de vulnerabilidades";
        $message = "🛡️ Reporte de Aegis Day0\n\n";

        foreach ($logs as $log) {
            $message .= "Fecha: {$log['date']}\n";
            $message .= "Plugin: {$log['plugin']}\n";
            $message .= "Tipo: {$log['type']}\n";
            $message .= "Severidad: {$log['severity']}\n";
            $message .= "Fuente: {$log['source']}\n";
            $message .= "Acción: {$log['action']}\n";
            $message .= "-----------------------------\n";
        }

        foreach ($emails as $email) {
            wp_mail($email, $subject, $message);
        }
    }
}
