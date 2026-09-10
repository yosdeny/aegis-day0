<?php
class Aegis_Day0_Logger {

    private static $max_logs = 1000; // Limit logs to prevent database bloat

    public static function add_log($plugin, $type, $severity, $source, $action) {
        // Sanitize inputs
        $plugin   = sanitize_text_field($plugin);
        $type     = sanitize_text_field($type);
        $severity = sanitize_text_field($severity);
        $source   = sanitize_text_field($source);
        $action   = sanitize_text_field($action);
        
        $logs = get_option('aegis_day0_logs', []);
        $logs[] = [
            'date'     => current_time('mysql'),
            'plugin'   => $plugin,
            'type'     => $type,
            'severity' => $severity,
            'source'   => $source,
            'action'   => $action
        ];
        
        // Keep only the last N logs to prevent database bloat
        if (count($logs) > self::$max_logs) {
            $logs = array_slice($logs, -self::$max_logs);
        }
        
        update_option('aegis_day0_logs', $logs);
    }

    public static function get_logs() {
        return get_option('aegis_day0_logs', []);
    }

    public static function export_logs($format = 'csv') {
        $logs = self::get_logs();
        if (empty($logs)) {
            return '';
        }

        if ($format === 'csv') {
            $output = "Fecha,Plugin,Tipo,Severidad,Fuente,Acción\n";
            foreach ($logs as $log) {
                // Escape CSV fields properly
                $row = [
                    self::escape_csv($log['date']),
                    self::escape_csv($log['plugin']),
                    self::escape_csv($log['type']),
                    self::escape_csv($log['severity']),
                    self::escape_csv($log['source']),
                    self::escape_csv($log['action'])
                ];
                $output .= implode(',', $row) . "\n";
            }
            return $output;
        } elseif ($format === 'json') {
            return json_encode($logs, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
        }
        return '';
    }
    
    /**
     * Escape a field for CSV output
     */
    private static function escape_csv($field) {
        $field = (string) $field;
        // If field contains comma, quote, or newline, wrap in quotes and escape quotes
        if (strpos($field, ',') !== false || strpos($field, '"') !== false || strpos($field, "\n") !== false) {
            $field = '"' . str_replace('"', '""', $field) . '"';
        }
        return $field;
    }
}
