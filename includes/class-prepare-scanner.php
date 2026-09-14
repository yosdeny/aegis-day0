<?php
/**
 * Escáner estático para detectar mal uso de wpdb::prepare()
 * 
 * Analiza el código fuente buscando llamadas a $wpdb->prepare() y verifica
 * que el número de marcadores (%s, %d, %f) coincida con los argumentos pasados.
 * 
 * @package Aegis_Day0
 */

if (!defined('ABSPATH')) {
    exit;
}

class Aegis_Prepare_Scanner {
    
    /**
     * Escanear un plugin en busca de mal uso de wpdb::prepare()
     * 
     * @param string $plugin_file Ruta del plugin (ej: my-plugin/my-plugin.php)
     * @return array Lista de issues encontrados
     */
    public function scan_plugin($plugin_file) {
        $issues = [];
        
        // Obtener ruta absoluta del plugin
        $plugin_path = WP_PLUGIN_DIR . '/' . dirname($plugin_file);
        
        // Obtener todos los archivos PHP del plugin
        $php_files = $this->get_php_files($plugin_path);
        
        foreach ($php_files as $file) {
            $file_issues = $this->scan_file($file);
            foreach ($file_issues as $issue) {
                // Añadir información del archivo relativo al plugin
                $issue['file_path'] = str_replace($plugin_path . '/', '', $file);
                $issues[] = $issue;
            }
        }
        
        return $issues;
    }
    
    /**
     * Escanear un archivo PHP en busca de mal uso de wpdb::prepare()
     * 
     * @param string $file Ruta absoluta del archivo
     * @return array Lista de issues encontrados
     */
    private function scan_file($file) {
        $issues = [];
        $content = file_get_contents($file);
        $lines = explode("\n", $content);
        
        // Patrón para encontrar llamadas a $wpdb->prepare() o self::$wpdb->prepare()
        // Captura: 1) la consulta SQL, 2) los argumentos
        $pattern = '/\$wpdb\s*(?:\s*::\s*\$wpdb)?\s*->\s*prepare\s*\(\s*(.*?)\s*(?:,\s*(.*?))?\s*\)/i';
        
        foreach ($lines as $line_num => $line) {
            if (preg_match_all($pattern, $line, $matches, PREG_SET_ORDER)) {
                foreach ($matches as $match) {
                    $sql_part = isset($match[1]) ? trim($match[1]) : '';
                    $args_part = isset($match[2]) ? trim($match[2]) : '';
                    
                    // Contar marcadores en la consulta SQL
                    $marker_count = $this->count_markers($sql_part);
                    
                    // Contar argumentos pasados
                    $arg_count = $this->count_arguments($args_part);
                    
                    // Si hay discrepancia, reportar el issue
                    if ($marker_count !== $arg_count && $marker_count > 0) {
                        $issues[] = [
                            'type' => 'Incorrect wpdb::prepare usage',
                            'severity' => 'Low',
                            'function' => 'wpdb::prepare',
                            'line' => $line_num + 1,
                            'message' => sprintf(
                                'Mismatch: %d markers but %d arguments passed',
                                $marker_count,
                                $arg_count
                            ),
                            'markers_found' => $marker_count,
                            'arguments_passed' => $arg_count,
                            'sql_preview' => $this->truncate_sql($sql_part),
                            'code_snippet' => $this->get_code_snippet($lines, $line_num)
                        ];
                    }
                }
            }
        }
        
        return $issues;
    }
    
    /**
     * Contar marcadores de posición en una cadena SQL
     * Marcadores soportados: %s, %d, %f, %% (escaped percent)
     * 
     * @param string $sql Cadena SQL
     * @return int Número de marcadores
     */
    private function count_markers($sql) {
        // Remover strings literales para no contar % dentro de ellos
        $cleaned = preg_replace('/\'(?:[^\'\\\\]|\\\\.)*\'|"(?:[^"\\\\]|\\\\.)*"/', "''", $sql);
        
        // No contar %% (porcentaje escapado)
        $cleaned = str_replace('%%', '', $cleaned);
        
        // Contar %s, %d, %f
        preg_match_all('/%[sdf]/i', $cleaned, $matches);
        
        return count($matches[0]);
    }
    
    /**
     * Contar argumentos en una llamada a prepare()
     * Maneja casos simples separados por coma
     * 
     * @param string $args Cadena de argumentos
     * @return int Número de argumentos
     */
    private function count_arguments($args) {
        if (empty(trim($args))) {
            return 0;
        }
        
        // Caso especial: array como único argumento
        if (preg_match('/^array\s*\(/i', $args) || preg_match('/^\[/', $args)) {
            // Contar elementos dentro del array
            preg_match_all('/%[sdf]/i', $args, $matches);
            return count($matches[0]);
        }
        
        // Contar argumentos separados por coma (simple, no maneja anidación compleja)
        $depth = 0;
        $count = 1;
        $in_string = false;
        $string_char = null;
        
        for ($i = 0; $i < strlen($args); $i++) {
            $char = $args[$i];
            
            // Manejo básico de strings
            if (($char === '"' || $char === "'") && ($i === 0 || $args[$i-1] !== '\\')) {
                if (!$in_string) {
                    $in_string = true;
                    $string_char = $char;
                } elseif ($char === $string_char) {
                    $in_string = false;
                    $string_char = null;
                }
            }
            
            // Solo contar comas fuera de strings y paréntesis
            if (!$in_string && $char === '(') {
                $depth++;
            } elseif (!$in_string && $char === ')') {
                $depth--;
            } elseif (!$in_string && $depth === 0 && $char === ',') {
                $count++;
            }
        }
        
        return $count;
    }
    
    /**
     * Truncar SQL para mostrarlo en el reporte
     * 
     * @param string $sql Cadena SQL
     * @param int $max_length Longitud máxima
     * @return string SQL truncado
     */
    private function truncate_sql($sql, $max_length = 80) {
        $sql = trim($sql);
        if (strlen($sql) > $max_length) {
            return substr($sql, 0, $max_length - 3) . '...';
        }
        return $sql;
    }
    
    /**
     * Obtener fragmento de código alrededor de la línea del error
     * 
     * @param array $lines Todas las líneas del archivo
     * @param int $line_num Número de línea del error (0-indexed)
     * @param int $context Líneas de contexto antes y después
     * @return array Fragmento de código con información de línea
     */
    private function get_code_snippet($lines, $line_num, $context = 2) {
        $snippet = [];
        $total_lines = count($lines);
        
        // Calcular rango de líneas a mostrar
        $start = max(0, $line_num - $context);
        $end = min($total_lines - 1, $line_num + $context);
        
        for ($i = $start; $i <= $end; $i++) {
            $snippet[] = [
                'line_number' => $i + 1,
                'code' => $lines[$i],
                'is_error_line' => ($i === $line_num)
            ];
        }
        
        return $snippet;
    }
    
    /**
     * Obtener todos los archivos PHP en un directorio
     * 
     * @param string $directory Directorio raíz
     * @return array Lista de rutas de archivos PHP
     */
    private function get_php_files($directory) {
        $files = [];
        
        if (!is_dir($directory)) {
            return $files;
        }
        
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($directory)
        );
        
        foreach ($iterator as $file) {
            if ($file->isFile() && strtolower($file->getExtension()) === 'php') {
                $files[] = $file->getPathname();
            }
        }
        
        return $files;
    }
}
