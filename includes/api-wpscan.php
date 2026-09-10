<?php
class Aegis_Day0_WPScan {

    private static $api_url = 'https://wpscan.com/api/v3/plugins/';
    private static $api_token = ''; // Aquí puedes colocar tu token de WPScan si lo tienes

    public static function check_plugin($plugin_name) {
        $issues = [];

        if (empty(self::$api_token)) {
            // Si no hay token, devolvemos vacío para evitar errores
            return $issues;
        }

        $url = self::$api_url . urlencode($plugin_name) . '?api_token=' . self::$api_token;
        $response = wp_remote_get($url);

        if (is_wp_error($response)) {
            return $issues;
        }

        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);

        if (!empty($data['vulnerabilities'])) {
            foreach ($data['vulnerabilities'] as $vuln) {
                $issues[] = [
                    'type'     => $vuln['title'],
                    'severity' => ucfirst(strtolower($vuln['severity']))
                ];
            }
        }

        return $issues;
    }
}
