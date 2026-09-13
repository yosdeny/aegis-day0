<?php
/**
 * Monitor de malas prácticas en wpdb::prepare
 * 
 * Intercepta los avisos de WordPress sobre uso incorrecto de prepare()
 * y los convierte en alertas escaneables para el panel de Aegis.
 */

if (!defined('ABSPATH')) {
    exit;
}

class Aegis_WPDB_Monitor {

    private static $detected_issues = [];
    private static $is_monitoring = false;

    /**
     * Iniciar el monitor de consultas
     * Debe llamarse antes de que se ejecuten las consultas de los plugins.
     */
    public static function start_monitoring() {
        if (self::$is_monitoring) {
            return;
        }

        // Hook crítico: WordPress llama a esto cuando hay un uso incorrecto
        add_filter('doing_it_wrong_run', [__CLASS__, 'catch_prepare_warning'], 10, 4);
        
        self::$is_monitoring = true;
    }

    /**
     * Captura el aviso de doing_it_wrong
     * 
     * @param null   $return
     * @param string $function Función llamada incorrectamente
     * @param string $message  Mensaje de error
     * @param string $version  Versión donde se añadió el aviso
     * @return null
     */
    public static function catch_prepare_warning($return, $function, $message, $version) {
        // Solo nos interesan los errores de wpdb::prepare
        if (strpos($message, 'wpdb::prepare') === false || strpos($message, 'marcadores') === false) {
            return $return;
        }

        // Analizar el mensaje para extraer detalles
        $details = self::parse_error_message($message);
        
        if ($details) {
            // Obtener el stack trace para encontrar el archivo REAL del plugin
            $caller_info = self::get_real_caller();
            
            if ($caller_info) {
                $issue = [
                    'type' => 'wpdb_prepare_mismatch',
                    'severity' => 'Low', // Mala práctica, no error crítico
                    'title' => 'Uso incorrecto de wpdb::prepare()',
                    'description' => 'La consulta SQL tiene un número incorrecto de marcadores (%s, %d) respecto a los argumentos pasados.',
                    'file' => $caller_info['file'],
                    'line' => $caller_info['line'],
                    'function' => $caller_info['function'] ?? 'unknown',
                    'details' => [
                        'expected_markers' => $details['expected'] ?? '?',
                        'provided_args' => $details['provided'] ?? '?',
                        'snippet' => 'Ver log de depuración para la consulta completa'
                    ],
                    'hash' => md5($caller_info['file'] . ':' . $caller_info['line'] . ':wpdb_prepare_mismatch')
                ];

                self::$detected_issues[] = $issue;
            }
        }

        return $return;
    }

    /**
     * Analiza el mensaje de error de WordPress para extraer números
     * Ejemplo: "...número correcto de marcadores (2) para el número de argumentos pasados (1)..."
     */
    private static function parse_error_message($message) {
        $expected = 0;
        $provided = 0;

        // Patrón en español: "marcadores (2) ... argumentos (1)"
        if (preg_match('/marcadores\s*\((\d+)\).*argumentos\s*(?:pasados)?\s*\((\d+)\)/i', $message, $matches)) {
            $expected = (int)$matches[1];
            $provided = (int)$matches[2];
        } 
        // Patrón en inglés (por si cambia el idioma): "placeholders (2) ... arguments (1)"
        elseif (preg_match('/placeholders?\s*\((\d+)\).*arguments?\s*\((\d+)\)/i', $message, $matches)) {
            $expected = (int)$matches[1];
            $provided = (int)$matches[2];
        }

        return [
            'expected' => $expected,
            'provided' => $provided
        ];
    }

    /**
     * Obtiene el archivo y línea reales desde el stack trace
     * WordPress reporta functions.php, necesitamos saltar hasta encontrar el plugin
     */
    private static function get_real_caller() {
        $trace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS);
        
        // Saltamos las primeras llamadas internas de WordPress y del propio monitor
        $skip_functions = [
            'catch_prepare_warning',
            'apply_filters',
            '_doing_it_wrong',
            'trigger_error',
            'prepare'
        ];

        foreach ($trace as $call) {
            if (isset($call['file']) && isset($call['line'])) {
                // Ignorar archivos core de WP
                if (strpos($call['file'], '/wp-includes/') !== false || strpos($call['file'], '/wp-admin/') !== false) {
                    continue;
                }
                
                // Ignorar nuestro propio plugin Aegis
                if (strpos($call['file'], '/aegis-security/') !== false || strpos($call['file'], '/aegis/') !== false) {
                    continue;
                }

                // Encontrado un archivo de plugin/tema externo
                return [
                    'file' => $call['file'],
                    'line' => $call['line'],
                    'function' => $call['function'] ?? null
                ];
            }
        }

        return null;
    }

    /**
     * Devuelve las incidencias detectadas durante la ejecución
     */
    public static function get_detected_issues() {
        return self::$detected_issues;
    }

    /**
     * Limpia las incidencias (útil para múltiples escaneos)
     */
    public static function clear_issues() {
        self::$detected_issues = [];
    }
}
