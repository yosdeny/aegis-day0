<?php
class Aegis_Day0_Scanner {

    public function run_checks() {
        // Only run for users with appropriate capabilities
        if (!current_user_can('manage_options') && !defined('WP_CLI') && !defined('DOING_CRON')) {
            return;
        }
        
        $plugins = get_plugins();
        $alerts = [];

        foreach ($plugins as $plugin_file => $plugin_data) {
            $plugin_name = sanitize_text_field($plugin_data['Name']);

            // Static scan
            $issues = $this->static_scan($plugin_file);
            foreach ($issues as $issue) {
                $alerts[] = [
                    'plugin'   => $plugin_name,
                    'type'     => sanitize_text_field($issue['type']),
                    'severity' => sanitize_text_field($issue['severity']),
                    'source'   => 'Static Scan'
                ];
                Aegis_Day0_Logger::add_log($plugin_name, $issue['type'], $issue['severity'], 'Static Scan', 'Detectado');
                Aegis_Day0_Notify::alert_admin($plugin_name, $issue['type'], $issue['severity']);
                $this->maybe_disable_plugin($plugin_file, $issue['severity']);
            }

            // WPScan query
            $wpscan_issues = Aegis_Day0_WPScan::check_plugin($plugin_name);
            foreach ($wpscan_issues as $issue) {
                $alerts[] = [
                    'plugin'   => $plugin_name,
                    'type'     => $issue['type'], // Already sanitized in WPScan class
                    'severity' => $issue['severity'], // Already sanitized in WPScan class
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
        
        // Validate file path to prevent directory traversal
        $real_path = realpath($plugin_path);
        if (!$real_path || strpos($real_path, WP_PLUGIN_DIR) !== 0) {
            return $issues;
        }
        
        if (!file_exists($real_path) || !is_readable($real_path)) {
            return $issues;
        }

        $content = @file_get_contents($real_path);
        if ($content === false) {
            return $issues;
        }

        foreach (Aegis_Day0_Rules::get_rules() as $rule) {
            if (@preg_match($rule['pattern'], $content)) {
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
            // Prevent disabling critical WordPress plugins
            $critical_plugins = ['wordpress-seo/wp-seo.php', 'woocommerce/woocommerce.php'];
            if (in_array($plugin_file, $critical_plugins, true)) {
                Aegis_Day0_Logger::add_log(
                    $plugin_file, 
                    'Auto-disable skipped', 
                    'Critical', 
                    'System', 
                    'Plugin crítico - no desactivar automáticamente'
                );
                return;
            }
            
            deactivate_plugins($plugin_file);
            Aegis_Day0_Logger::add_log($plugin_file, 'Auto-disable', 'Critical', 'System', 'Plugin desactivado');
        }
    }
}
