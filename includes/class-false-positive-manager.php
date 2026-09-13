<?php
/**
 * Gestor de Falsos Positivos para Aegis Day0
 * 
 * Permite marcar reportes como falsos positivos y evita sobre-revisión.
 * Si un archivo tiene un nuevo tipo de error, se limpian todos los falsos positivos asociados.
 * 
 * @package Aegis_Day0
 * @since 0.5
 */

if (!defined('ABSPATH')) {
    exit;
}

class Aegis_False_Positive_Manager {
    
    /**
     * Nombre de la tabla en la base de datos
     */
    const TABLE_NAME = 'aegis_day0_false_positives';
    
    /**
     * Versión de la estructura de la tabla
     */
    const DB_VERSION = '1.0';
    
    /**
     * Inicializa el gestor de falsos positivos
     */
    public static function init() {
        add_action('admin_init', [__CLASS__, 'maybe_create_table']);
        add_action('wp_ajax_aegis_mark_false_positive', [__CLASS__, 'ajax_mark_false_positive']);
        add_action('wp_ajax_aegis_remove_false_positive', [__CLASS__, 'ajax_remove_false_positive']);
        add_filter('aegis_day0_filter_alerts', [__CLASS__, 'filter_alerts'], 10, 2);
    }
    
    /**
     * Crea la tabla de falsos positivos si no existe
     */
    public static function maybe_create_table() {
        global $wpdb;
        
        $table_name = $wpdb->prefix . self::TABLE_NAME;
        $charset_collate = $wpdb->get_charset_collate();
        
        $current_version = get_option('aegis_day0_fp_db_version', '0');
        
        if (version_compare($current_version, self::DB_VERSION, '<')) {
            $sql = "CREATE TABLE $table_name (
                id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
                plugin_file varchar(255) NOT NULL,
                file_path varchar(512) NOT NULL,
                issue_type varchar(100) NOT NULL,
                issue_hash varchar(64) NOT NULL,
                marked_by bigint(20) UNSIGNED NOT NULL,
                marked_at datetime DEFAULT CURRENT_TIMESTAMP NOT NULL,
                notes text,
                PRIMARY KEY  (id),
                KEY plugin_file (plugin_file),
                KEY file_path (file_path(255)),
                KEY issue_hash (issue_hash),
                UNIQUE KEY unique_fp (plugin_file, file_path, issue_hash)
            ) $charset_collate;";
            
            require_once ABSPATH . 'wp-admin/includes/upgrade.php';
            dbDelta($sql);
            
            update_option('aegis_day0_fp_db_version', self::DB_VERSION);
        }
    }
    
    /**
     * Genera un hash único para un reporte basado en el tipo de issue y contexto
     * 
     * @param array $issue Datos del issue
     * @param bool $for_storage Si es true, normaliza el type a 'fp_marker' para consistencia
     * @return string Hash del reporte
     */
    public static function generate_issue_hash($issue, $for_storage = false) {
        $issue_type = isset($issue['type']) ? $issue['type'] : '';
        
        // Normalizar el tipo de issue para FPs guardados para evitar inconsistencias
        if ($for_storage) {
            $issue_type = 'fp_marker';
        }
        
        $hash_data = [
            'type' => $issue_type,
            'function' => isset($issue['function']) ? $issue['function'] : '',
            'line' => isset($issue['line']) ? $issue['line'] : 0,
            'severity' => isset($issue['severity']) ? $issue['severity'] : '',
            'source' => isset($issue['source']) ? $issue['source'] : ''
        ];
        
        return md5(serialize($hash_data));
    }
    
    /**
     * Marca un reporte como falso positivo
     * 
     * @param string $plugin_file Archivo del plugin (ej: 'my-plugin/my-plugin.php')
     * @param string $file_path Ruta completa del archivo dentro del plugin
     * @param array $issue Datos del issue a marcar como falso positivo
     * @param string $notes Notas opcionales sobre por qué es falso positivo
     * @return bool|WP_Error True si éxito, WP_Error si falla
     */
    public static function mark_as_false_positive($plugin_file, $file_path, $issue, $notes = '') {
        global $wpdb;
        
        if (!current_user_can('manage_options')) {
            return new WP_Error('forbidden', __('No tienes permisos para realizar esta acción.', 'aegis-day0'));
        }
        
        $table_name = $wpdb->prefix . self::TABLE_NAME;
        // Usar for_storage=true para generar hash consistente con el guardado
        $issue_hash = self::generate_issue_hash($issue, true);
        $user_id = get_current_user_id();
        
        // Verificar si ya existe
        $exists = $wpdb->get_var($wpdb->prepare(
            "SELECT id FROM $table_name WHERE plugin_file = %s AND file_path = %s AND issue_hash = %s",
            $plugin_file,
            $file_path,
            $issue_hash
        ));
        
        if ($exists) {
            return true; // Ya está marcado
        }
        
        // El issue_type ya viene normalizado a 'fp_marker' desde ajax_mark_false_positive
        // Solo sanitizar y guardar
        $issue_type_sanitized = isset($issue['type']) ? sanitize_text_field($issue['type']) : 'fp_marker';
        $issue_type_sanitized = substr($issue_type_sanitized, 0, 50);
        
        $result = $wpdb->insert(
            $table_name,
            [
                'plugin_file' => sanitize_text_field($plugin_file),
                'file_path' => sanitize_text_field($file_path),
                'issue_type' => $issue_type_sanitized,
                'issue_hash' => $issue_hash,
                'marked_by' => $user_id,
                'notes' => sanitize_textarea_field($notes)
            ],
            ['%s', '%s', '%s', '%s', '%d', '%s']
        );
        
        if ($result === false) {
            return new WP_Error('db_error', __('Error al guardar el falso positivo.', 'aegis-day0'));
        }
        
        return true;
    }
    
    /**
     * Limpia todos los falsos positivos de un archivo específico
     * Esto se hace cuando se detecta un NUEVO tipo de error en ese archivo
     * 
     * @param string $plugin_file Archivo del plugin
     * @param string $file_path Ruta del archivo dentro del plugin
     */
    public static function clear_file_false_positives($plugin_file, $file_path) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . self::TABLE_NAME;
        
        $wpdb->delete(
            $table_name,
            [
                'plugin_file' => $plugin_file,
                'file_path' => $file_path
            ],
            ['%s', '%s']
        );
    }
    
    /**
     * Obtiene todos los hashes de falsos positivos para un plugin y archivo
     * 
     * @param string $plugin_file Archivo del plugin
     * @param string|null $file_path Ruta del archivo (null para todos los archivos del plugin, '*' para comodín)
     * @return array Array de hashes de issues marcados como falsos positivos
     */
    public static function get_false_positives($plugin_file, $file_path = null) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . self::TABLE_NAME;
        
        // Si file_path es '*' o null, obtener todos los FPs del plugin
        if ($file_path === null || $file_path === '*') {
            $results = $wpdb->get_results($wpdb->prepare(
                "SELECT issue_hash, issue_type, file_path, marked_at, notes 
                 FROM $table_name 
                 WHERE plugin_file = %s
                 ORDER BY marked_at DESC",
                $plugin_file
            ), ARRAY_A);
        } else {
            $results = $wpdb->get_results($wpdb->prepare(
                "SELECT issue_hash, issue_type, marked_at, notes 
                 FROM $table_name 
                 WHERE plugin_file = %s AND file_path = %s
                 ORDER BY marked_at DESC",
                $plugin_file,
                $file_path
            ), ARRAY_A);
        }
        
        if (!$results) {
            return [];
        }
        
        return $results;
    }
    
    /**
     * Verifica si un issue específico está marcado como falso positivo
     * 
     * @param string $plugin_file Archivo del plugin
     * @param string $file_path Ruta del archivo (puede ser '*' para comodín)
     * @param array $issue Datos del issue
     * @return bool True si es falso positivo, False si no
     */
    public static function is_false_positive($plugin_file, $file_path, $issue) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . self::TABLE_NAME;
        // Usar for_storage=true para generar hash consistente con el guardado
        $issue_hash = self::generate_issue_hash($issue, true);
        
        // Si file_path es '*', buscar en todos los archivos del plugin
        if ($file_path === '*') {
            $exists = $wpdb->get_var($wpdb->prepare(
                "SELECT id FROM $table_name 
                 WHERE plugin_file = %s AND issue_hash = %s",
                $plugin_file,
                $issue_hash
            ));
        } else {
            $exists = $wpdb->get_var($wpdb->prepare(
                "SELECT id FROM $table_name 
                 WHERE plugin_file = %s AND file_path = %s AND issue_hash = %s",
                $plugin_file,
                $file_path,
                $issue_hash
            ));
        }
        
        return (bool) $exists;
    }
    
    /**
     * Filtra las alertas removiendo las marcadas como falsos positivos
     * También limpia el estado si hay nuevos tipos de errores en un archivo
     * 
     * @param array $alerts Alertas detectadas
     * @param string $plugin_file Archivo del plugin
     * @return array Alertas filtradas
     */
    public static function filter_alerts($alerts, $plugin_file) {
        global $wpdb;
        
        if (empty($alerts)) {
            return [];
        }
        
        $table_name = $wpdb->prefix . self::TABLE_NAME;
        $filtered_alerts = [];
        $files_with_new_errors = [];
        
        // Paso 1: Agrupar alertas por archivo y detectar cuáles tienen errores nuevos
        $alerts_by_file = [];
        $alerts_without_file = []; // Para alertas sin file_path específico
        
        foreach ($alerts as $alert) {
            // Soporte para diferentes nombres de claves
            $file_path = isset($alert['file']) ? $alert['file'] : (isset($alert['file_path']) ? $alert['file_path'] : '');
            
            if (empty($file_path)) {
                // Si no tiene file, guardarlas separadamente para procesar con FP globales del plugin
                $alerts_without_file[] = $alert;
                continue;
            }
            
            $key = $plugin_file . '|' . $file_path;
            
            if (!isset($alerts_by_file[$key])) {
                $alerts_by_file[$key] = [
                    'plugin_file' => $plugin_file,
                    'file_path' => $file_path,
                    'alerts' => [],
                    'hashes' => []
                ];
            }
            
            $issue_hash = self::generate_issue_hash($alert, true);
            $alerts_by_file[$key]['alerts'][] = $alert;
            $alerts_by_file[$key]['hashes'][] = $issue_hash;
        }
        
        // Procesar alertas sin file_path específico (FP a nivel de plugin)
        if (!empty($alerts_without_file)) {
            // Obtener FPs globales del plugin (file_path = '*')
            $global_fps = self::get_false_positives($plugin_file, '*');
            $global_fp_hashes = wp_list_pluck($global_fps, 'issue_hash');
            
            foreach ($alerts_without_file as $alert) {
                $h = self::generate_issue_hash($alert, true);
                if (in_array($h, $global_fp_hashes)) {
                    $alert['is_false_positive'] = true;
                } else {
                    $alert['is_false_positive'] = false;
                }
                $filtered_alerts[] = $alert;
            }
        }
        
        // Paso 2: Para cada archivo, verificar si hay errores nuevos (no marcados como FP)
        foreach ($alerts_by_file as $key => $data) {
            $p_file = $data['plugin_file'];
            $f_path = $data['file_path'];
            $current_hashes = $data['hashes'];
            
            // Obtener hashes de FPs guardados para este archivo
            $existing_fps = self::get_false_positives($p_file, $f_path);
            $known_fp_hashes = wp_list_pluck($existing_fps, 'issue_hash');
            
            // Detectar si hay ALGÚN error nuevo (no conocido como FP)
            $has_new_error = false;
            foreach ($current_hashes as $h) {
                if (!in_array($h, $known_fp_hashes)) {
                    $has_new_error = true;
                    break;
                }
            }
            
            if ($has_new_error) {
                // Hay un error nuevo en un archivo con FPs previos
                // Regla: Limpiar TODOS los FPs de este archivo y re-reportar TODOS los errores
                $files_with_new_errors[] = ['plugin_file' => $p_file, 'file_path' => $f_path];
                
                // Añadir todas las alertas de este archivo marcadas como NO-FP
                foreach ($data['alerts'] as $alert) {
                    $alert['is_false_positive'] = false;
                    $filtered_alerts[] = $alert;
                }
            } else {
                // No hay errores nuevos. Todos los errores actuales son FPs conocidos.
                // Filtrar: ocultar los que están en la lista de FPs
                foreach ($data['alerts'] as $alert) {
                    $h = self::generate_issue_hash($alert, true);
                    if (in_array($h, $known_fp_hashes)) {
                        $alert['is_false_positive'] = true;
                    } else {
                        $alert['is_false_positive'] = false;
                    }
                    $filtered_alerts[] = $alert;
                }
            }
        }
        
        // Paso 3: Ejecutar limpieza en BD si hubo nuevos errores y guardar snapshot actualizado
        if (!empty($files_with_new_errors)) {
            foreach ($files_with_new_errors as $file) {
                self::clear_file_false_positives($file['plugin_file'], $file['file_path']);
            }
        }
        
        return $filtered_alerts;
    }
    
    /**
     * Remueve un falso positivo específico
     * 
     * @param int $fp_id ID del falso positivo a remover
     * @return bool|WP_Error True si éxito, WP_Error si falla
     */
    public static function remove_false_positive($fp_id) {
        global $wpdb;
        
        if (!current_user_can('manage_options')) {
            return new WP_Error('forbidden', __('No tienes permisos para realizar esta acción.', 'aegis-day0'));
        }
        
        $table_name = $wpdb->prefix . self::TABLE_NAME;
        
        $result = $wpdb->delete(
            $table_name,
            ['id' => $fp_id],
            ['%d']
        );
        
        if ($result === false) {
            return new WP_Error('db_error', __('Error al remover el falso positivo.', 'aegis-day0'));
        }
        
        return true;
    }
    
    /**
     * Handler AJAX para marcar como falso positivo
     */
    public static function ajax_mark_false_positive() {
        check_ajax_referer('aegis_day0_nonce', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Permiso denegado', 'aegis-day0')]);
            return;
        }
        
        // Obtener y validar datos - convertir null a string vacío antes de sanitizar
        $plugin_file = isset($_POST['plugin_file']) ? sanitize_text_field((string) $_POST['plugin_file']) : '';
        $file_path = isset($_POST['file_path']) ? sanitize_text_field((string) $_POST['file_path']) : '';
        $issue_type_raw = isset($_POST['issue_type']) ? sanitize_text_field((string) $_POST['issue_type']) : '';
        $issue_function = isset($_POST['issue_function']) ? sanitize_text_field((string) $_POST['issue_function']) : '';
        $issue_line = isset($_POST['issue_line']) ? intval($_POST['issue_line']) : 0;
        $issue_severity = isset($_POST['issue_severity']) ? sanitize_text_field((string) $_POST['issue_severity']) : '';
        $issue_source = isset($_POST['issue_source']) ? sanitize_text_field((string) $_POST['issue_source']) : '';
        $notes = isset($_POST['notes']) ? sanitize_textarea_field((string) $_POST['notes']) : '';
        
        // Validar solo plugin_file (file_path es opcional para marcar todo el plugin)
        if (empty($plugin_file)) {
            wp_send_json_error(['message' => __('Datos incompletos: falta el archivo del plugin', 'aegis-day0')]);
            return;
        }
        
        // Si file_path está vacío, usamos un valor comodín para marcar todo el plugin
        if (empty($file_path)) {
            $file_path = '*'; // Comodín para todos los archivos
        }
        
        // Normalizar issue_type: siempre usar 'fp_marker' para consistencia en el hash
        // El tipo original se guarda solo como referencia informativa
        $issue_type = 'fp_marker';
        
        $issue = [
            'type' => $issue_type,
            'function' => $issue_function,
            'line' => $issue_line,
            'severity' => $issue_severity,
            'source' => $issue_source
        ];
        
        $result = self::mark_as_false_positive($plugin_file, $file_path, $issue, $notes);
        
        if (is_wp_error($result)) {
            wp_send_json_error(['message' => $result->get_error_message()]);
            return;
        }
        
        // Guardar snapshot actualizado después de marcar FP
        self::save_fp_snapshot($plugin_file);
        
        wp_send_json_success(['message' => __('Reporte marcado como falso positivo', 'aegis-day0')]);
    }
    
    /**
     * Handler AJAX para remover falso positivo
     */
    public static function ajax_remove_false_positive() {
        check_ajax_referer('aegis_day0_nonce', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Permiso denegado', 'aegis-day0')]);
            return;
        }
        
        $fp_id = isset($_POST['fp_id']) ? intval($_POST['fp_id']) : 0;
        
        if ($fp_id <= 0) {
            wp_send_json_error(['message' => __('ID inválido', 'aegis-day0')]);
            return;
        }
        
        $result = self::remove_false_positive($fp_id);
        
        if (is_wp_error($result)) {
            wp_send_json_error(['message' => $result->get_error_message()]);
            return;
        }
        
        // Obtener el plugin_file para actualizar el snapshot
        global $wpdb;
        $table_name = $wpdb->prefix . self::TABLE_NAME;
        $plugin_file = $wpdb->get_var($wpdb->prepare(
            "SELECT plugin_file FROM $table_name WHERE id = %d",
            $fp_id
        ));
        
        // Actualizar snapshot si tenemos el plugin_file
        if ($plugin_file) {
            self::save_fp_snapshot($plugin_file);
        }
        
        wp_send_json_success(['message' => __('Falso positivo removido', 'aegis-day0')]);
    }
    
    /**
     * Obtiene estadísticas de falsos positivos
     * 
     * @return array Estadísticas
     */
    public static function get_statistics() {
        global $wpdb;
        
        $table_name = $wpdb->prefix . self::TABLE_NAME;
        
        $total = $wpdb->get_var("SELECT COUNT(*) FROM $table_name");
        
        $by_plugin = $wpdb->get_results(
            "SELECT plugin_file, COUNT(*) as count 
             FROM $table_name 
             GROUP BY plugin_file 
             ORDER BY count DESC",
            ARRAY_A
        );
        
        $recent = $wpdb->get_results(
            "SELECT * FROM $table_name 
             ORDER BY marked_at DESC 
             LIMIT 10",
            ARRAY_A
        );
        
        return [
            'total' => (int) $total,
            'by_plugin' => $by_plugin,
            'recent' => $recent
        ];
    }
    
    /**
     * Guarda el snapshot actual de falsos positivos para un plugin
     * Lógica simple: Guardar solo la lista ordenada de issue_hashes de los FPs.
     * 
     * @param string $plugin_file Archivo del plugin
     * @return bool True si éxito, False si falla
     */
    public static function save_fp_snapshot($plugin_file) {
        global $wpdb;
        
        // 1. Obtener solo los hashes de los FPs actuales para este plugin
        $table_name = $wpdb->prefix . self::TABLE_NAME;
        $fps = $wpdb->get_col($wpdb->prepare(
            "SELECT issue_hash FROM $table_name WHERE plugin_file = %s ORDER BY issue_hash",
            $plugin_file
        ));

        // 2. Guardar directamente el array de hashes (serializado por WP)
        $option_name = 'aegis_day0_fp_log_' . md5($plugin_file);
        
        // Si está vacío, guardamos array vacío para indicar "revisado y limpio"
        if (empty($fps)) {
            $fps = [];
        }

        update_option($option_name, $fps, 'no');

        return true;
    }
    
    /**
     * Compara el log guardado con el estado actual de FPs
     * Lógica simple: Comparar dos arrays de hashes. Si son iguales, no hay cambios.
     * 
     * @param string $plugin_file Archivo del plugin
     * @return array ['has_changes' => bool, 'new_count' => int, 'old_count' => int]
     */
    public static function compare_fp_snapshot($plugin_file) {
        global $wpdb;
        
        $option_name = 'aegis_day0_fp_log_' . md5($plugin_file);
        $saved_log = get_option($option_name);
        
        // Si no hay log guardado, es la primera vez -> hay cambios (todo es nuevo)
        if ($saved_log === false) {
            return [
                'has_changes' => true,
                'new_count' => 0,
                'old_count' => 0,
                'message' => 'Sin historial previo - Primera revisión requerida'
            ];
        }
        
        // Asegurar que sea un array
        if (!is_array($saved_log)) {
            $saved_log = [];
        }
        
        // Obtener estado actual directamente de la BD (solo hashes)
        $table_name = $wpdb->prefix . self::TABLE_NAME;
        $current_log = $wpdb->get_col($wpdb->prepare(
            "SELECT issue_hash FROM $table_name WHERE plugin_file = %s ORDER BY issue_hash",
            $plugin_file
        ));
        
        if (!is_array($current_log)) {
            $current_log = [];
        }
        
        // Comparación directa de arrays ordenados
        // Como ambos vienen ordenados por SQL, una comparación simple basta
        $has_changes = ($saved_log !== $current_log);
        
        return [
            'has_changes' => $has_changes,
            'new_count' => count($current_log),
            'old_count' => count($saved_log),
            'message' => $has_changes ? 'Cambios detectados - Nueva revisión requerida' : 'Sin cambios - Todo revisado',
            'hash_match' => !$has_changes
        ];
    }
    
    /**
     * Limpia el snapshot guardado para un plugin
     * 
     * @param string $plugin_file Archivo del plugin
     */
    public static function clear_fp_snapshot($plugin_file) {
        delete_option('aegis_day0_fp_log_' . md5($plugin_file));
    }
}

// Inicializar el gestor
Aegis_False_Positive_Manager::init();
