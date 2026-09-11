<?php
class Aegis_Day0_WPScan {

    private static $api_url = 'https://wpscan.com/api/v3/plugins/';

    /**
     * Verifica vulnerabilidades de un plugin usando WPScan API
     * 
     * @param string $plugin_name Nombre del plugin a verificar
     * @return array Lista de vulnerabilidades encontradas
     */
    public static function check_plugin($plugin_name) {
        $issues = [];

        // Get API token from WordPress options (secure storage)
        $api_token = get_option('aegis_day0_wpscan_token', '');
        
        if (empty($api_token)) {
            // If no token, return empty to avoid errors
            return $issues;
        }

        // Usar header Authorization en lugar de parámetro URL para mayor seguridad
        $url = self::$api_url . urlencode($plugin_name) . '/';
        $response = wp_remote_get($url, [
            'timeout' => 15,
            'user-agent' => 'Aegis-Day0/' . AEGIS_DAY0_VERSION,
            'sslverify' => true,
            'headers' => [
                'Authorization' => 'Token ' . $api_token,
                'Accept' => 'application/json'
            ]
        ]);

        if (is_wp_error($response)) {
            // Log error for debugging
            error_log('Aegis Day0 WPScan API Error: ' . $response->get_error_message());
            return $issues;
        }

        // Validate HTTP response code
        $status_code = wp_remote_retrieve_response_code($response);
        if ($status_code !== 200) {
            error_log('Aegis Day0 WPScan API returned status code: ' . $status_code);
            return $issues;
        }

        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);

        // Validate JSON response
        if (json_last_error() !== JSON_ERROR_NONE || !is_array($data)) {
            error_log('Aegis Day0 WPScan API invalid JSON response');
            return $issues;
        }

        if (!empty($data['vulnerabilities']) && is_array($data['vulnerabilities'])) {
            foreach ($data['vulnerabilities'] as $vuln) {
                // Validación estricta de tipos para prevenir XSS si WPScan es comprometido
                if (!isset($vuln['title']) || !isset($vuln['severity'])) {
                    continue;
                }
                
                // Validar que los campos sean del tipo correcto
                if (!is_string($vuln['title']) || !is_string($vuln['severity'])) {
                    error_log('Aegis Day0 WPScan API: Invalid data types in vulnerability response');
                    continue;
                }
                
                $issues[] = [
                    'type'     => sanitize_text_field($vuln['title']),
                    'severity' => ucfirst(strtolower(sanitize_text_field($vuln['severity'])))
                ];
            }
        }

        return $issues;
    }
}
