<?php
class Aegis_Day0_Logger {

    public static function add_log($plugin, $type, $severity, $source, $action) {
        $logs = get_option('aegis_day0_logs', []);
        $logs[] = [
            'date'     => current_time('mysql'),
            'plugin'   => $plugin,
            'type'     => $type,
            'severity' => $severity,
            'source'   => $source,
            'action'   => $action
        ];
        update_option('aegis_day0_logs', $logs);
    }

    public static function get_logs() {
        return get_option('aegis_day0_logs', []);
    }

    public static function export_logs($format = 'csv') {
        $logs = self::get_logs();
        if (empty($logs)) return '';

        if ($format === 'csv') {
            $output = "Fecha,Plugin,Tipo,Severidad,Fuente,Acción\n";
            foreach ($logs as $log) {
                $output .= "{$log['date']},{$log['plugin']},{$log['type']},{$log['severity']},{$log['source']},{$log['action']}\n";
            }
            return $output;
        } elseif ($format === 'json') {
            return json_encode($logs, JSON_PRETTY_PRINT);
        }
        return '';
    }
}
