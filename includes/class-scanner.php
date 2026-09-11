<?php

if (!defined('ABSPATH')) {
    exit;
}

class Aegis_Day0_Scanner {
    
    /**
     * Instancia del analizador de tokens
     */
    private $token_analyzer;
    
    /**
     * Instancia del analizador AST
     */
    private $ast_analyzer;
    
    /**
     * Constructor - inicializa los analizadores
     */
    public function __construct() {
        if (class_exists('Aegis_Token_Analyzer')) {
            $this->token_analyzer = new Aegis_Token_Analyzer();
        }
        if (class_exists('Aegis_AST_Analyzer')) {
            $this->ast_analyzer = new Aegis_AST_Analyzer();
        }
    }

    public function run_checks() {
        // Only run for users with appropriate capabilities or in CLI/CRON context
        if (!current_user_can('manage_options') && !defined('WP_CLI') && !defined('DOING_CRON')) {
            return;
        }
        
        // Prevent running on every admin page load - use caching
        $last_scan = get_transient('aegis_day0_last_scan');
        if ($last_scan && !defined('WP_CLI') && !defined('DOING_CRON')) {
            return; // Skip if scanned within last hour
        }
        set_transient('aegis_day0_last_scan', time(), HOUR_IN_SECONDS);
        
        $plugins = get_plugins();
        $alerts = [];
        $processed_alerts = []; // Track unique alerts to prevent duplicates within same scan
        
        // Get previously notified alerts to avoid sending duplicate notifications
        $previously_notified = get_option('aegis_day0_notified_alerts', []);
        $currently_detected = []; // Track what's currently detected
        $new_notifications = []; // Track new alerts to notify

        foreach ($plugins as $plugin_file => $plugin_data) {
            $plugin_name = sanitize_text_field($plugin_data['Name']);

            // Static scan con reglas regex (método tradicional)
            $issues = $this->static_scan($plugin_file);
            foreach ($issues as $issue) {
                // Create unique key to prevent duplicate alerts
                $alert_key = md5($plugin_name . '|' . $issue['type'] . '|' . $issue['severity']);
                
                if (!isset($processed_alerts[$alert_key])) {
                    $processed_alerts[$alert_key] = true;
                    
                    $alerts[] = [
                        'plugin'   => $plugin_name,
                        'type'     => sanitize_text_field($issue['type']),
                        'severity' => sanitize_text_field($issue['severity']),
                        'source'   => 'Static Scan',
                        'false_positive_risk' => isset($issue['false_positive_risk']) ? $issue['false_positive_risk'] : 'unknown'
                    ];
                    
                    // Track this detection
                    $currently_detected[$alert_key] = true;
                    
                    Aegis_Day0_Logger::add_log(
                        $plugin_name, 
                        $issue['type'], 
                        $issue['severity'], 
                        'Static Scan', 
                        'Detectado'
                    );
                    
                    // Only send notification for non-low severity issues AND if not previously notified
                    if ($issue['severity'] !== 'Low' && !isset($previously_notified[$alert_key])) {
                        Aegis_Day0_Notify::alert_admin($plugin_name, $issue['type'], $issue['severity']);
                        $new_notifications[$alert_key] = [
                            'plugin' => $plugin_name,
                            'type' => $issue['type'],
                            'severity' => $issue['severity'],
                            'time' => current_time('mysql')
                        ];
                    }
                    
                    // Only auto-disable for Critical severity with low false positive risk
                    if ($issue['severity'] === 'Critical' && 
                        isset($issue['false_positive_risk']) && 
                        $issue['false_positive_risk'] === 'low') {
                        $this->maybe_disable_plugin($plugin_file, $issue['severity']);
                    }
                }
            }
            
            // Token-based analysis (nuevo método avanzado)
            if ($this->token_analyzer) {
                $token_issues = $this->token_based_scan($plugin_file);
                foreach ($token_issues as $issue) {
                    $alert_key = md5($plugin_name . '|' . $issue['type'] . '|' . $issue['function'] . '|' . $issue['line']);
                    
                    if (!isset($processed_alerts[$alert_key])) {
                        $processed_alerts[$alert_key] = true;
                        
                        $alerts[] = [
                            'plugin'   => $plugin_name,
                            'type'     => sanitize_text_field($issue['type']),
                            'severity' => sanitize_text_field($issue['severity']),
                            'source'   => 'Token Analysis',
                            'false_positive_risk' => isset($issue['false_positive_risk']) ? $issue['false_positive_risk'] : 'unknown',
                            'function' => isset($issue['function']) ? $issue['function'] : '',
                            'line' => isset($issue['line']) ? $issue['line'] : 0
                        ];
                        
                        // Track this detection
                        $currently_detected[$alert_key] = true;
                        
                        Aegis_Day0_Logger::add_log(
                            $plugin_name, 
                            $issue['type'], 
                            $issue['severity'], 
                            'Token Analysis', 
                            sprintf('Línea %d: %s', $issue['line'], $issue['function'])
                        );
                        
                        // Only send notification for non-low severity issues AND if not previously notified
                        if ($issue['severity'] !== 'Low' && !isset($previously_notified[$alert_key])) {
                            Aegis_Day0_Notify::alert_admin($plugin_name, $issue['type'], $issue['severity']);
                            $new_notifications[$alert_key] = [
                                'plugin' => $plugin_name,
                                'type' => $issue['type'],
                                'severity' => $issue['severity'],
                                'time' => current_time('mysql')
                            ];
                        }
                        
                        // Auto-disable solo para críticos con bajo riesgo de falso positivo
                        if ($issue['severity'] === 'Critical' && 
                            isset($issue['false_positive_risk']) && 
                            $issue['false_positive_risk'] === 'low') {
                            $this->maybe_disable_plugin($plugin_file, $issue['severity']);
                        }
                    }
                }
            }

            // AST-based analysis (análisis más preciso con PHP-Parser)
            if ($this->ast_analyzer) {
                $ast_issues = $this->ast_based_scan($plugin_file);
                foreach ($ast_issues as $issue) {
                    $alert_key = md5($plugin_name . '|' . $issue['type'] . '|' . $issue['function'] . '|' . $issue['line'] . '|AST');

                    if (!isset($processed_alerts[$alert_key])) {
                        $processed_alerts[$alert_key] = true;

                        $alerts[] = [
                            'plugin'   => $plugin_name,
                            'type'     => sanitize_text_field($issue['type']),
                            'severity' => sanitize_text_field($issue['severity']),
                            'source'   => 'AST Analysis',
                            'false_positive_risk' => isset($issue['false_positive_risk']) ? $issue['false_positive_risk'] : 'unknown',
                            'function' => isset($issue['function']) ? $issue['function'] : '',
                            'line' => isset($issue['line']) ? $issue['line'] : 0
                        ];

                        // Track this detection
                        $currently_detected[$alert_key] = true;

                        Aegis_Day0_Logger::add_log(
                            $plugin_name,
                            $issue['type'],
                            $issue['severity'],
                            'AST Analysis',
                            sprintf('Línea %d: %s - %s', $issue['line'], $issue['function'], $issue['description'])
                        );

                        // Only send notification for non-low severity issues AND if not previously notified
                        if ($issue['severity'] !== 'Low' && !isset($previously_notified[$alert_key])) {
                            Aegis_Day0_Notify::alert_admin($plugin_name, $issue['type'], $issue['severity']);
                            $new_notifications[$alert_key] = [
                                'plugin' => $plugin_name,
                                'type' => $issue['type'],
                                'severity' => $issue['severity'],
                                'time' => current_time('mysql')
                            ];
                        }

                        // Auto-disable solo para críticos con bajo riesgo de falso positivo
                        if ($issue['severity'] === 'Critical' &&
                            isset($issue['false_positive_risk']) &&
                            $issue['false_positive_risk'] === 'low') {
                            $this->maybe_disable_plugin($plugin_file, $issue['severity']);
                        }
                    }
                }
            }

            // WPScan query
            $wpscan_issues = Aegis_Day0_WPScan::check_plugin($plugin_name);
            foreach ($wpscan_issues as $issue) {
                // Create unique key to prevent duplicate alerts
                $alert_key = md5($plugin_name . '|' . $issue['type'] . '|' . $issue['severity']);
                
                if (!isset($processed_alerts[$alert_key])) {
                    $processed_alerts[$alert_key] = true;
                    
                    $alerts[] = [
                        'plugin'   => $plugin_name,
                        'type'     => sanitize_text_field($issue['type']),
                        'severity' => sanitize_text_field($issue['severity']),
                        'source'   => 'WPScan'
                    ];
                    
                    // Track this detection
                    $currently_detected[$alert_key] = true;
                    
                    Aegis_Day0_Logger::add_log(
                        $plugin_name, 
                        $issue['type'], 
                        $issue['severity'], 
                        'WPScan', 
                        'Detectado'
                    );
                    
                    // Only send notification if not previously notified
                    if (!isset($previously_notified[$alert_key])) {
                        Aegis_Day0_Notify::alert_admin($plugin_name, $issue['type'], $issue['severity']);
                        $new_notifications[$alert_key] = [
                            'plugin' => $plugin_name,
                            'type' => $issue['type'],
                            'severity' => $issue['severity'],
                            'time' => current_time('mysql')
                        ];
                    }
                    $this->maybe_disable_plugin($plugin_file, $issue['severity']);
                }
            }
        }

        update_option('aegis_day0_alerts', $alerts);
        
        // Merge previous notifications with currently detected ones to maintain state
        // Only keep notifications for vulnerabilities that are still present
        $updated_notifications = array_intersect_key($previously_notified, $currently_detected);
        
        // Add new notifications
        $final_notifications = array_merge($updated_notifications, $new_notifications);
        
        // Save the updated notification state
        update_option('aegis_day0_notified_alerts', $final_notifications);
    }

    /**
     * Escaneo basado en análisis de tokens PHP
     * 
     * @param string $plugin_file Archivo del plugin
     * @return array Issues encontrados
     */
    private function token_based_scan($plugin_file) {
        $issues = [];
        
        if (!$this->token_analyzer) {
            return $issues;
        }
        
        $plugin_path = WP_PLUGIN_DIR . '/' . $plugin_file;
        
        // Validate file path to prevent directory traversal
        $real_path = realpath($plugin_path);
        if (!$real_path || strpos($real_path, WP_PLUGIN_DIR) !== 0) {
            return $issues;
        }
        
        if (!file_exists($real_path) || !is_readable($real_path)) {
            return $issues;
        }
        
        // Usar el analizador de tokens
        $alerts = $this->token_analyzer->analyze_file($real_path);
        
        foreach ($alerts as $alert) {
            $issues[] = [
                'type' => isset($alert['description']) ? $alert['description'] : 'Función peligrosa detectada',
                'severity' => isset($alert['severity']) ? ucfirst($alert['severity']) : 'Medium',
                'false_positive_risk' => isset($alert['false_positive_risk']) ? $alert['false_positive_risk'] : 'medium',
                'function' => isset($alert['function']) ? $alert['function'] : '',
                'line' => isset($alert['line']) ? $alert['line'] : 0,
                'context' => isset($alert['context']) ? $alert['context'] : '',
                'recommendation' => isset($alert['recommendation']) ? $alert['recommendation'] : ''
            ];
        }
        
        return $issues;
    }

    /**
     * Escaneo basado en análisis AST con PHP-Parser
     *
     * @param string $plugin_file Archivo del plugin
     * @return array Issues encontrados
     */
    private function ast_based_scan($plugin_file) {
        $issues = [];

        if (!$this->ast_analyzer) {
            return $issues;
        }

        $plugin_path = WP_PLUGIN_DIR . '/' . $plugin_file;

        // Validate file path to prevent directory traversal
        $real_path = realpath($plugin_path);
        if (!$real_path || strpos($real_path, WP_PLUGIN_DIR) !== 0) {
            return $issues;
        }

        if (!file_exists($real_path) || !is_readable($real_path)) {
            return $issues;
        }

        // Usar el analizador AST
        $alerts = $this->ast_analyzer->analyze_file($real_path);

        foreach ($alerts as $alert) {
            $issues[] = [
                'type' => isset($alert['description']) ? $alert['description'] : 'Patrón peligroso detectado vía AST',
                'severity' => isset($alert['severity']) ? ucfirst($alert['severity']) : 'Medium',
                'false_positive_risk' => isset($alert['false_positive_risk']) ? $alert['false_positive_risk'] : 'medium',
                'function' => isset($alert['function']) ? $alert['function'] : '',
                'line' => isset($alert['line']) ? $alert['line'] : 0,
                'description' => isset($alert['description']) ? $alert['description'] : '',
                'recommendation' => isset($alert['recommendation']) ? $alert['recommendation'] : ''
            ];
        }

        return $issues;
    }

    private function static_scan($plugin_file) {
        $issues = [];
        $plugin_path = WP_PLUGIN_DIR . '/' . $plugin_file;

        // Validate file path to prevent directory traversal
        $real_path = realpath($plugin_path);
        if (!$real_path || strpos($real_path, WP_PLUGIN_DIR) !== 0) {
            return $issues;
        }

        // Escanear todos los archivos PHP del plugin, no solo el archivo principal
        $php_files = $this->get_all_php_files($real_path);
        
        foreach ($php_files as $file_path) {
            $file_issues = $this->scan_file($file_path);
            $issues = array_merge($issues, $file_issues);
        }

        return $issues;
    }

    /**
     * Obtener todos los archivos PHP de un directorio recursivamente
     */
    private function get_all_php_files($dir) {
        $files = [];
        
        if (!is_dir($dir)) {
            return $files;
        }

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS)
        );

        foreach ($iterator as $file) {
            if ($file->isFile() && strtolower($file->getExtension()) === 'php') {
                $files[] = $file->getPathname();
            }
        }

        return $files;
    }

    /**
     * Escanear un archivo individual en busca de vulnerabilidades
     */
    private function scan_file($file_path) {
        $issues = [];

        if (!file_exists($file_path) || !is_readable($file_path)) {
            return $issues;
        }

        $content = @file_get_contents($file_path);
        if ($content === false) {
            return $issues;
        }

        foreach (Aegis_Day0_Rules::get_rules() as $rule) {
            if (@preg_match($rule['pattern'], $content, $matches, PREG_OFFSET_CAPTURE)) {
                // Apply contextual filtering to reduce false positives
                if (method_exists('Aegis_Day0_Rules', 'should_report')) {
                    if (!Aegis_Day0_Rules::should_report($rule, $content, $matches[0][1])) {
                        continue;
                    }
                }

                $issues[] = [
                    'type'     => $rule['description'],
                    'severity' => $rule['severity'],
                    'false_positive_risk' => isset($rule['false_positive_risk']) ? $rule['false_positive_risk'] : 'unknown',
                    'file'     => basename($file_path),
                    'line'     => $this->get_line_number($content, $matches[0][1])
                ];
            }
        }

        return $issues;
    }

    /**
     * Obtener número de línea desde un offset en el contenido
     */
    private function get_line_number($content, $offset) {
        $lines = substr($content, 0, $offset);
        return substr_count($lines, "\n") + 1;
    }

    /**
     * Desactiva automáticamente un plugin si es crítico y tiene vulnerabilidad severa
     * 
     * @param string $plugin_file Archivo del plugin
     * @param string $severity Severidad de la vulnerabilidad
     */
    private function maybe_disable_plugin($plugin_file, $severity) {
        $auto_disable = get_option('aegis_day0_auto_disable', 0);
        
        // Only auto-disable for Critical severity issues
        if ($auto_disable && $severity === 'Critical') {
            // Lista de plugins críticos que no deben desactivarse automáticamente
            // Aplicar filtro para permitir personalización por el sitio
            $critical_plugins = apply_filters(
                'aegis_day0_critical_plugins',
                [
                    'wordpress-seo/wp-seo.php', 
                    'woocommerce/woocommerce.php',
                    'akismet/akismet.php',
                    'classic-editor/classic-editor.php'
                ]
            );
            
            if (in_array($plugin_file, $critical_plugins, true)) {
                Aegis_Day0_Logger::add_log(
                    $plugin_file, 
                    'Auto-disable skipped', 
                    'Critical', 
                    'System', 
                    'Plugin crítico del sistema - no desactivar automáticamente'
                );
                return;
            }
            
            // Get plugin info for logging
            $plugins = get_plugins();
            $plugin_name = isset($plugins[$plugin_file]) ? $plugins[$plugin_file]['Name'] : $plugin_file;
            
            // Log the action before disabling
            Aegis_Day0_Logger::add_log(
                $plugin_name, 
                'Auto-disable triggered', 
                'Critical', 
                'System', 
                'Plugin desactivado por vulnerabilidad crítica detectada'
            );
            
            // Deactivate the plugin
            deactivate_plugins($plugin_file);
            
            // Send immediate notification about the auto-disable action
            $admin_email = get_option('admin_email');
            if (is_email($admin_email)) {
                $subject = __('🚨 Aegis Day0 - Plugin desactivado automáticamente', 'aegis-day0');
                $message = sprintf(
                    __("El plugin '%s' ha sido desactivado automáticamente debido a una vulnerabilidad crítica detectada.\n\nPor favor, revise el dashboard de Aegis Day0 para más detalles.", 'aegis-day0'),
                    $plugin_name
                );
                wp_mail(
                    sanitize_email($admin_email), 
                    $subject, 
                    $message, 
                    ['Content-Type: text/plain; charset=UTF-8']
                );
            }
        }
    }
}
