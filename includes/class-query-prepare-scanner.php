<?php
/**
 * Escáner Estático para validar llamadas a $wpdb->prepare()
 * 
 * Detecta desajustes entre marcadores (%s, %d, %f) y argumentos pasados
 * antes de que ocurra la ejecución, reportándolo como una detección en el panel.
 *
 * @package Aegis_Day0
 */

if (!defined('ABSPATH')) {
    exit;
}

class GRM_Query_Prepare_Scanner {

    /**
     * Resultados del escaneo actual
     */
    private static $issues = array();

    /**
     * Inicializar el escáner (no hacer nada automáticamente)
     * El escaneo se realiza on-demand cuando se llama a scan_plugin()
     */
    public static function init() {
        // No registrar actions automáticamente para evitar duplicados
        // El escaneo se invoca desde Aegis_Day0_Scanner
    }

    /**
     * Escanear un plugin específico en busca de errores wpdb::prepare()
     * 
     * @param string $plugin_file Ruta relativa del plugin (ej: my-plugin/my-plugin.php)
     * @return array Array de issues encontrados
     */
    public function scan_plugin($plugin_file) {
        self::$issues = array(); // Resetear issues anteriores
        
        $plugin_path = WP_PLUGIN_DIR . '/' . $plugin_file;
        
        // Validar ruta para prevenir directory traversal
        $real_path = realpath($plugin_path);
        if (!$real_path || strpos($real_path, WP_PLUGIN_DIR) !== 0) {
            return array();
        }
        
        // Obtener todos los archivos PHP del plugin
        $php_files = $this->get_php_files($real_path);
        
        foreach ($php_files as $file) {
            $this->analyze_file($file, $plugin_file);
        }
        
        return self::$issues;
    }

    /**
     * Obtener todos los archivos PHP recursivamente
     */
    private function get_php_files($path) {
        $files = array();
        if (is_dir($path)) {
            $iterator = new RecursiveDirectoryIterator($path);
            $filter = new RecursiveCallbackFilterIterator($iterator, function($current, $key, $iterator) {
                // Excluir directorios comunes que no necesitamos escanear
                $name = $current->getFilename();
                if ($current->isDir()) {
                    return !in_array($name, array('.', '..', 'node_modules', 'vendor', '.git', 'tests', 'test'));
                }
                return $current->getExtension() === 'php';
            });
            
            $recursive = new RecursiveIteratorIterator($filter);
            
            foreach ($recursive as $file) {
                if ($file->isFile()) {
                    $files[] = $file->getPathname();
                }
            }
        }
        return $files;
    }

    /**
     * Analizar un archivo en busca de llamadas a prepare()
     */
    private function analyze_file($file_path, $plugin_file) {
        $content = file_get_contents($file_path);
        if ($content === false) {
            return;
        }
        
        // Patrón para encontrar $wpdb->prepare(..., ...)
        // Captura: 1) La consulta SQL, 2) Los argumentos (si existen)
        $pattern = '/\$wpdb\s*->\s*prepare\s*\(\s*(.*?)\s*(?:,\s*(.*?))?\s*\)/is';

        preg_match_all($pattern, $content, $matches, PREG_SET_ORDER | PREG_OFFSET_CAPTURE);

        foreach ($matches as $match) {
            $full_match = $match[0][0];
            $offset = $match[0][1];
            
            // Calcular el número de línea aproximado
            $line_number = substr_count(substr($content, 0, $offset), "\n") + 1;

            $query_part = isset($match[1]) ? trim($match[1][0]) : '';
            $args_part = isset($match[2]) ? trim($match[2][0]) : '';

            // Contar marcadores y argumentos
            $markers_count = self::count_placeholders($query_part);
            $args_count = self::count_arguments($args_part);

            if ($markers_count !== $args_count) {
                self::report_error($file_path, $plugin_file, $line_number, $full_match, $markers_count, $args_count);
            }
        }
    }

    /**
     * Contar marcadores válidos (%s, %d, %f, %i) en la string de consulta
     */
    private static function count_placeholders($query_string) {
        // Eliminar strings escapados o comentarios dentro de la query si es posible
        // Buscar patrones %s, %d, %f, %i (nuevo en WP 6.2 para integers)
        // Evitar contar %% (escape de porcentaje)
        
        $cleaned = str_replace('%%', '', $query_string); // Quitar escapes de %
        preg_match_all('/%[sdfi]/', $cleaned, $matches);
        return count($matches[0]);
    }

    /**
     * Contar argumentos reales pasados a la función
     * Esto es complejo porque los argumentos pueden ser funciones, arrays, o concatenaciones.
     * Estrategia: Contar comas a nivel superior, pero tener cuidado con comas dentro de strings o arrays.
     */
    private static function count_arguments($args_string) {
        if (empty(trim($args_string))) {
            return 0;
        }

        // Si el primer argumento es un array explícito array(...) o [...], 
        // la lógica de conteo cambia. 
        // wpdb->prepare acepta: prepare(sql, $var1, $var2) O prepare(sql, array($var1, $var2))
        
        if (strpos($args_string, 'array(') === 0 || strpos($args_string, '[') === 0) {
            return self::count_array_elements($args_string);
        }

        // Caso estándar: arg1, arg2, arg3
        // Contamos comas que estén al nivel principal (no dentro de funciones anidadas)
        $level = 0;
        $count = 1; // Al menos 1 argumento si la string no está vacía
        
        $len = strlen($args_string);
        for ($i = 0; $i < $len; $i++) {
            $char = $args_string[$i];
            if ($char === '(' || $char === '[') {
                $level++;
            } elseif ($char === ')' || $char === ']') {
                $level--;
            } elseif ($char === ',' && $level === 0) {
                $count++;
            }
        }
        return $count;
    }

    /**
     * Contador auxiliar para elementos de array
     */
    private static function count_array_elements($str) {
        // Eliminar 'array(' y ')' final o corchetes
        $clean = trim($str);
        if (strpos($clean, 'array(') === 0) {
            $clean = substr($clean, 6, -1);
        } elseif (strpos($clean, '[') === 0) {
            $clean = substr($clean, 1, -1);
        }

        if (trim($clean) === '') return 0;

        $level = 0;
        $count = 1;
        $len = strlen($clean);
        for ($i = 0; $i < $len; $i++) {
            $char = $clean[$i];
            if ($char === '(' || $char === '[') {
                $level++;
            } elseif ($char === ')' || $char === ']') {
                $level--;
            } elseif ($char === ',' && $level === 0) {
                $count++;
            }
        }
        return $count;
    }

    /**
     * Reportar el error al sistema de detecciones
     */
    private static function report_error($file_path, $plugin_file, $line, $code, $markers, $args) {
        // Ruta relativa para mostrar en el panel
        $relative_path = str_replace(WP_PLUGIN_DIR . '/', '', $file_path);
        
        $message = sprintf(
            "wpdb::prepare incorrecta: Se encontraron %d marcadores pero se pasaron %d argumentos.",
            $markers,
            $args
        );

        $detail = sprintf(
            "Línea %d: %s\nMarcadores: %d | Argumentos: %d",
            $line,
            trim(str_replace("\n", " ", $code)),
            $markers,
            $args
        );

        // Agregar a la lista de issues
        self::$issues[] = array(
            'type' => 'wpdb Prepare Mismatch',
            'file_path' => $relative_path,
            'line' => $line,
            'message' => $message,
            'severity' => 'low',
            'function' => 'wpdb::prepare',
            'description' => $detail
        );
        
        // También escribir en error_log para desarrollo inmediato
        error_log("[AEGIS PREPARE SCAN] $message en $relative_path:$line");
    }
}
