<?php
class Aegis_Day0_Reports {

    public static function send_report() {
        // Verify this is running in a proper context
        if (!function_exists('get_option')) {
            return;
        }
        
        $logs = get_option('aegis_day0_logs', []);
        if (empty($logs)) {
            return;
        }

        // If no recipients configured, use admin_email by default
        $recipients = get_option('aegis_day0_report_recipients', '');
        if (empty($recipients)) {
            $recipients = get_option('admin_email');
        }

        // Sanitize and validate email addresses
        $emails = array_map('trim', explode(',', $recipients));
        $valid_emails = [];
        foreach ($emails as $email) {
            if (is_email($email)) {
                $valid_emails[] = sanitize_email($email);
            }
        }
        
        if (empty($valid_emails)) {
            return;
        }

        $subject = __('Aegis Day0 - Reporte de vulnerabilidades', 'aegis-day0');
        $message = "🛡️ " . __('Reporte de Aegis Day0', 'aegis-day0') . "\n\n";

        foreach ($logs as $log) {
            $message .= sprintf(
                "%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s\n",
                __('Fecha', 'aegis-day0'), esc_html($log['date']),
                __('Plugin', 'aegis-day0'), esc_html($log['plugin']),
                __('Tipo', 'aegis-day0'), esc_html($log['type']),
                __('Severidad', 'aegis-day0'), esc_html($log['severity']),
                __('Fuente', 'aegis-day0'), esc_html($log['source']),
                __('Acción', 'aegis-day0'), esc_html($log['action']),
                "-----------------------------"
            );
        }
        
        $headers = ['Content-Type: text/plain; charset=UTF-8'];

        foreach ($valid_emails as $email) {
            wp_mail($email, $subject, $message, $headers);
        }
    }
}
