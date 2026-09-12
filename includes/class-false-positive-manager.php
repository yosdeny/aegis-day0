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
     * @return string Hash del reporte
     */
    public static function generate_issue_hash($issue) {
        $hash_data = [
            'type' => isset($issue['type']) ? $issue['type'] : '',
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
        $issue_hash = self::generate_issue_hash($issue);
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
        
        $result = $wpdb->insert(
            $table_name,
            [
                'plugin_file' => sanitize_text_field($plugin_file),
                'file_path' => sanitize_text_field($file_path),
                'issue_type' => sanitize_text_field($issue['type']),
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
     * @param string|null $file_path Ruta del archivo (null para todos los archivos del plugin)
     * @return array Array de hashes de issues marcados como falsos positivos
     */
    public static function get_false_positives($plugin_file, $file_path = null) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . self::TABLE_NAME;
        
        if ($file_path === null) {
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
     * @param string $file_path Ruta del archivo
     * @param array $issue Datos del issue
     * @return bool True si es falso positivo, False si no
     */
    public static function is_false_positive($plugin_file, $file_path, $issue) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . self::TABLE_NAME;
        $issue_hash = self::generate_issue_hash($issue);
        
        $exists = $wpdb->get_var($wpdb->prepare(
            "SELECT id FROM $table_name 
             WHERE plugin_file = %s AND file_path = %s AND issue_hash = %s",
            $plugin_file,
            $file_path,
            $issue_hash
        ));
        
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
        $filtered_alerts = [];
        $files_with_new_errors = []; // Track files that have new error types
        
        // Primero, identificar qué archivos tienen nuevos tipos de errores
        foreach ($alerts as $alert) {
            if (!isset($alert['file'])) {
                continue;
            }
            
            $file_path = $alert['file'];
            $issue_hash = self::generate_issue_hash($alert);
            
            // Obtener falsos positivos existentes para este archivo
            $existing_fps = self::get_false_positives($plugin_file, $file_path);
            $existing_hashes = wp_list_pluck($existing_fps, 'issue_hash');
            
            // Si este tipo de error NO está en los falsos positivos, es un error nuevo
            if (!in_array($issue_hash, $existing_hashes)) {
                // Marcar este archivo para limpiar sus falsos positivos
                $files_with_new_errors[$plugin_file . '|' . $file_path] = true;
            }
        }
        
        // Limpiar falsos positivos de archivos con nuevos errores
        foreach ($files_with_new_errors as $key => $value) {
            list($p_file, $f_path) = explode('|', $key);
            self::clear_file_false_positives($p_file, $f_path);
        }
        
        // Ahora filtrar las alertas
        foreach ($alerts as $alert) {
            if (!isset($alert['file'])) {
                // Si no tiene file, incluir la alerta
                $filtered_alerts[] = $alert;
                continue;
            }
            
            $file_path = $alert['file'];
            
            // Verificar si es falso positivo
            if (self::is_false_positive($plugin_file, $file_path, $alert)) {
                // Marcar como falso positivo en la alerta para UI
                $alert['is_false_positive'] = true;
                // No incluir en alertas activas
                continue;
            }
            
            $filtered_alerts[] = $alert;
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
        
        $plugin_file = isset($_POST['plugin_file']) ? sanitize_text_field($_POST['plugin_file']) : '';
        $file_path = isset($_POST['file_path']) ? sanitize_text_field($_POST['file_path']) : '';
        $issue_type = isset($_POST['issue_type']) ? sanitize_text_field($_POST['issue_type']) : '';
        $issue_function = isset($_POST['issue_function']) ? sanitize_text_field($_POST['issue_function']) : '';
        $issue_line = isset($_POST['issue_line']) ? intval($_POST['issue_line']) : 0;
        $issue_severity = isset($_POST['issue_severity']) ? sanitize_text_field($_POST['issue_severity']) : '';
        $issue_source = isset($_POST['issue_source']) ? sanitize_text_field($_POST['issue_source']) : '';
        $notes = isset($_POST['notes']) ? sanitize_textarea_field($_POST['notes']) : '';
        
        if (empty($plugin_file) || empty($file_path) || empty($issue_type)) {
            wp_send_json_error(['message' => __('Datos incompletos', 'aegis-day0')]);
            return;
        }
        
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
}

// Inicializar el gestor
Aegis_False_Positive_Manager::init();
