<?php
class Aegis_Day0_Rules {

    public static function get_rules() {
        return [
            // Critical - Dangerous functions with high confidence (variable input)
            [
                'pattern'     => '/\beval\s*\([^)]*\$\w+/i',  // eval with variable input
                'description' => 'Uso peligroso de eval() con variables',
                'severity'    => 'Critical',
                'false_positive_risk' => 'low'
            ],
            [
                'pattern'     => '/\b(shell_exec|system|passthru|exec)\s*\([^)]*\$\w+/i',  // command execution with variables
                'description' => 'Ejecución de comandos con entrada dinámica',
                'severity'    => 'Critical',
                'false_positive_risk' => 'low'
            ],
            // High - Potentially dangerous but needs context
            [
                'pattern'     => '/\bbase64_decode\s*\([^)]*\$\w+/i',  // base64_decode with variable
                'description' => 'Uso de base64_decode() con variables',
                'severity'    => 'High',
                'false_positive_risk' => 'medium'
            ],
            [
                'pattern'     => '/\bunserialize\s*\([^)]*\$(?!wpdb)/i',  // unserialize with variable (excluding $wpdb)
                'description' => 'Uso de unserialize() con entrada no confiable',
                'severity'    => 'High',
                'false_positive_risk' => 'medium'
            ],
            // Medium - Common patterns that need review
            [
                'pattern'     => '/\$wpdb->query\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)/i',  // direct SQL with superglobals
                'description' => 'Consulta SQL directa con superglobales',
                'severity'    => 'High',
                'false_positive_risk' => 'low'
            ],
            [
                'pattern'     => '/echo\s+\$_(GET|POST|REQUEST|COOKIE)\s*[;)]/i',  // direct echo of superglobals
                'description' => 'Salida directa de superglobales sin escapar',
                'severity'    => 'Medium',
                'false_positive_risk' => 'low'
            ],
            // Low - Informational only, reduced severity (catches all uses for manual review)
            [
                'pattern'     => '/\b(eval|base64_decode|shell_exec|system|passthru|unserialize)\s*\(/i',
                'description' => 'Función potencialmente riesgosa detectada (revisar contexto)',
                'severity'    => 'Low',
                'false_positive_risk' => 'high',
                'contextual'    => true
            ]
        ];
    }
    
    /**
     * Check if a match should be reported based on context
     * @param array $rule The rule that matched
     * @param string $content The file content
     * @param int $match_offset The offset where the match occurred
     * @return bool True if should report, false if should skip
     */
    public static function should_report($rule, $content, $match_offset) {
        // If rule is marked as contextual, apply additional checks
        if (!empty($rule['contextual'])) {
            // Don't report if the function is inside a comment
            $before_match = substr($content, max(0, $match_offset - 200), 200);
            if (preg_match('/\/\/.*$|\/\*.*\*\//m', $before_match)) {
                return false;
            }
            
            // Don't report if it's in a safe context (e.g., sanitize_text_field, wp_kses)
            if (preg_match('/(sanitize_text_field|wp_kses|esc_html|esc_attr)\s*\([^)]*$/i', $before_match)) {
                return false;
            }
        }
        
        return true;
    }
}
