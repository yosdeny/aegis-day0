<?php
class Aegis_Day0_Rules {

    public static function get_rules() {
        return [
            [
                'pattern'     => '/eval\s*\(/i',
                'description' => 'Uso de eval()',
                'severity'    => 'Critical'
            ],
            [
                'pattern'     => '/base64_decode\s*\(/i',
                'description' => 'Uso de base64_decode()',
                'severity'    => 'High'
            ],
            [
                'pattern'     => '/shell_exec\s*\(/i',
                'description' => 'Uso de shell_exec()',
                'severity'    => 'Critical'
            ],
            [
                'pattern'     => '/system\s*\(/i',
                'description' => 'Uso de system()',
                'severity'    => 'Critical'
            ],
            [
                'pattern'     => '/passthru\s*\(/i',
                'description' => 'Uso de passthru()',
                'severity'    => 'Critical'
            ],
            [
                'pattern'     => '/unserialize\s*\(/i',
                'description' => 'Uso de unserialize() inseguro',
                'severity'    => 'High'
            ],
            [
                'pattern'     => '/\$wpdb->query\s*\(/i',
                'description' => 'Posible SQL Injection',
                'severity'    => 'High'
            ],
            [
                'pattern'     => '/echo\s+\$_(GET|POST|REQUEST|COOKIE)/i',
                'description' => 'Posible XSS reflejado',
                'severity'    => 'Medium'
            ],
            [
                'pattern'     => '/<script>/i',
                'description' => 'Inserción directa de JavaScript',
                'severity'    => 'Medium'
            ]
        ];
    }
}
