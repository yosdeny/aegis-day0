<?php
class Aegis_Day0_Scanner {

    public function run_checks() {
        $plugins = get_plugins();
        $alerts = [];

        foreach ($plugins as $plugin_file => $plugin_data) {
            $plugin_name = $plugin_data['Name'];

            // Escaneo estático
            $issues = $this->static_scan($plugin_file);
            foreach ($issues as $issue) {
                $alerts[] = [
                    'plugin'   => $plugin_name,
                    'type'     => $issue['type'],
                    'severity' => $issue['severity'],
                    'source'   => 'Static Scan'
                ];
                Aegis_Day0_Logger::add_log($plugin_name, $issue['type'], $issue['severity'], 'Static Scan', 'Detectado');
                Aegis_Day0_Notify::alert_admin($plugin_name, $issue['type'], $issue['severity']);
                $this->maybe_disable_plugin($plugin_file, $issue['severity']);
            }

            // Consulta WPScan
            $wpscan_issues = Aegis_Day0_WPScan::check_plugin($plugin_name);
            foreach ($wpscan_issues as $issue) {
                $alerts[] = [
                    'plugin'   => $plugin_name,
                    'type'     => $issue['type'],
                    'severity' => $issue['severity'],
                    'source'   => 'WPScan'
                ];
                Aegis_Day0_Logger::add_log($plugin_name, $issue['type'], $issue['severity'], 'WPScan', 'Detectado');
                Aegis_Day0_Notify::alert_admin($plugin_name, $issue['type'], $issue['severity']);
                $this->maybe_disable_plugin($plugin_file, $issue['severity']);
            }
        }

        update_option('aegis_day0_alerts', $alerts);
    }

    private function static_scan($plugin_file) {
        $issues = [];
        $plugin_path = WP_PLUGIN_DIR . '/' . $plugin_file;
        if (!file_exists($plugin_path)) return $issues;

        $content = file_get_contents($plugin_path);

        foreach (Aegis_Day0_Rules::get_rules() as $rule) {
            if (preg_match($rule['pattern'], $content)) {
                $issues[] = [
                    'type'     => $rule['description'],
                    'severity' => $rule['severity']
                ];
            }
        }

        return $issues;
    }

    private function maybe_disable_plugin($plugin_file, $severity) {
        $auto_disable = get_option('aegis_day0_auto_disable', 0);
        if ($auto_disable && $severity === 'Critical') {
            deactivate_plugins($plugin_file);
            Aegis_Day0_Logger::add_log($plugin_file, 'Auto-disable', 'Critical', 'System', 'Plugin desactivado');
        }
    }
}
