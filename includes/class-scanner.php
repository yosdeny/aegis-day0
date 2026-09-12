<?php
/**
 * Scanner class for Aegis Day-0
 */

if (!defined('ABSPATH')) exit;

class Aegis_Day0_Scanner {
    
    private $false_positive_manager;

    public function __construct() {
        require_once AEGIS_DAY0_PLUGIN_DIR . 'includes/class-false-positive-manager.php';
        $this->false_positive_manager = new Aegis_Day0_False_Positive_Manager();
    }

    /**
     * Run security checks on a plugin
     */
    public function run_checks($plugin_file, $plugin_data) {
        $results = array(
            'critical' => array(),
            'high' => array(),
            'medium' => array(),
            'low' => array(),
            'info' => array()
        );

        // Ruta absoluta para el archivo principal del plugin
        $absolute_main_path = WP_PLUGIN_DIR . '/' . $plugin_file;
        
        if (!file_exists($absolute_main_path)) {
            return $results;
        }

        // 1. Obtener lista de archivos a escanear
        $files_to_scan = $this->get_plugin_files($plugin_file);

        foreach ($files_to_scan as $file) {
            $full_path = WP_PLUGIN_DIR . '/' . $file;
            
            if (!file_exists($full_path)) {
                continue;
            }

            $content = file_get_contents($full_path);
            if (empty($content)) {
                continue;
            }

            // NORMALIZACIÓN DE RUTA: Clave para consistencia
            // 1. Reemplazar backslashes por forward slashes
            $relative_path = str_replace('\\', '/', $file);
            // 2. Asegurar que no tenga prefijo 'wp-content/plugins/' redundante si viene en la ruta
            if (strpos($relative_path, 'wp-content/plugins/') === 0) {
                $relative_path = substr($relative_path, strlen('wp-content/plugins/'));
            }

            // --- EJECUTAR CHECKS ---
            
            // Check 1: AST Analysis / Funciones Peligrosas (Medium/High/Critical)
            $ast_results = $this->check_ast($full_path, $content, $relative_path);
            foreach ($ast_results as $alert) {
                $this->add_alert($results, $alert);
            }

            // Check 2: Pattern Matching (Low/Medium)
            $pattern_results = $this->check_patterns($content, $relative_path);
            foreach ($pattern_results as $alert) {
                $this->add_alert($results, $alert);
            }
        }

        // Filtrar falsos positivos ANTES de retornar al dashboard
        return $this->false_positive_manager->filter_alerts($results, $plugin_file);
    }

    /**
     * Helper para añadir alerta validando estructura
     */
    private function add_alert(&$results, $alert) {
        $severity = strtolower($alert['severity']);
        
        // SEGURIDAD: Si no hay file_path, descartar la alerta (no debería ocurrir con la nueva lógica)
        if (empty($alert['file_path'])) {
            error_log("Aegis Internal Error: Alert generated without file_path. Discarding.");
            return; 
        }

        if (isset($results[$severity])) {
            $results[$severity][] = $alert;
        }
    }

    /**
     * AST Analysis Check (Simulado para ejemplo, reemplazar con php-parser real)
     */
    private function check_ast($file_path, $content, $relative_path) {
        $alerts = array();
        
        // Ejemplo: Detección de funciones peligrosas
        $dangerous_funcs = array('eval', 'base64_decode', 'gzinflate', 'rot13', 'system', 'exec');
        
        foreach ($dangerous_funcs as $func) {
            // Búsqueda simple (mejorar con AST real en producción)
            if (preg_match_all('/' . preg_quote($func) . '\s*\(/i', $content, $matches, PREG_OFFSET_CAPTURE)) {
                foreach ($matches[0] as $match) {
                    $line_number = $this->get_line_number($content, $match[1]);
                    
                    // CONSTRUCCIÓN SEGURA: file_path inyectado explícitamente
                    $alerts[] = array(
                        'type' => 'AST Analysis',
                        'severity' => 'Medium', 
                        'message' => "Uso de función peligrosa: {$func}()",
                        'file_path' => $relative_path, // CRÍTICO: Siempre presente
                        'line' => $line_number,
                        'code_snippet' => $this->get_code_snippet($content, $line_number),
                        'issue_hash' => md5($relative_path . ':' . $line_number . ':' . $func) // Hash consistente
                    );
                }
            }
        }

        return $alerts;
    }

    /**
     * Pattern Matching Check (Regex)
     */
    private function check_patterns($content, $relative_path) {
        $alerts = array();

        // Patrones de bajo nivel (falsos positivos comunes)
        $patterns = array(
            array(
                'regex' => '/\$_GET\s*\[|\$_POST\s*\[|\$_REQUEST\s*\[/i',
                'severity' => 'Low',
                'message' => 'Uso directo de variables superglobales sin sanitizar aparente',
                'type' => 'Pattern Match'
            ),
            array(
                'regex' => '/wp_insert_post\s*\(/i',
                'severity' => 'Low',
                'message' => 'Creación dinámica de posts detectada',
                'type' => 'Pattern Match'
            ),
            array(
                'regex' => '/file_get_contents\s*\(/i',
                'severity' => 'Low',
                'message' => 'Lectura de archivos detectada',
                'type' => 'Pattern Match'
            )
        );

        foreach ($patterns as $pattern) {
            if (preg_match_all($pattern['regex'], $content, $matches, PREG_OFFSET_CAPTURE)) {
                foreach ($matches[0] as $match) {
                    $line_number = $this->get_line_number($content, $match[1]);
                    
                    // CONSTRUCCIÓN SEGURA: file_path inyectado explícitamente
                    $alerts[] = array(
                        'type' => $pattern['type'],
                        'severity' => $pattern['severity'],
                        'message' => $pattern['message'],
                        'file_path' => $relative_path, // CRÍTICO: Siempre presente
                        'line' => $line_number,
                        'code_snippet' => $this->get_code_snippet($content, $line_number),
                        'issue_hash' => md5($relative_path . ':' . $line_number . ':' . $pattern['message'])
                    );
                }
            }
        }

        return $alerts;
    }

    /**
     * Obtener lista de archivos del plugin
     */
    private function get_plugin_files($plugin_file) {
        $files = array();
        $plugin_dir = WP_PLUGIN_DIR . '/' . dirname($plugin_file);
        
        if (is_dir($plugin_dir)) {
            // Ignorar directorios ocultos y vendor si es posible
            $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($plugin_dir));
            foreach ($iterator as $file) {
                if ($file->isFile() && in_array($file->getExtension(), array('php', 'js', 'html'))) {
                    $full_path = $file->getPathname();
                    $relative = str_replace(WP_PLUGIN_DIR . '/', '', $full_path);
                    $files[] = str_replace('\\', '/', $relative);
                }
            }
        } else {
            // Plugin de un solo archivo
            $files[] = $plugin_file;
        }
        
        return $files;
    }

    private function get_line_number($content, $offset) {
        return substr_count($content, "\n", 0, $offset) + 1;
    }

    private function get_code_snippet($content, $line_number, $lines_around = 2) {
        $lines = explode("\n", $content);
        $start = max(0, $line_number - 1 - $lines_around);
        $end = min(count($lines), $line_number - 1 + $lines_around + 1);
        return implode("\n", array_slice($lines, $start, $end - $start));
    }
}
