<?php
/**
 * Aegis Day0 - Configuración Centralizada
 * 
 * Archivo de configuración central para listas de funciones peligrosas,
 * funciones de sanitización y otros patrones de seguridad.
 * 
 * @package Aegis_Day0
 * @since 0.5
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Obtener lista centralizada de funciones peligrosas
 * 
 * Esta función proporciona una única fuente de verdad para las funciones
 * peligrosas que deben ser monitoreadas por el analizador de tokens y AST.
 * 
 * @return array Lista de funciones peligrosas con su severidad y riesgo de falso positivo
 */
function aegis_day0_get_dangerous_functions() {
    return apply_filters('aegis_day0_dangerous_functions', [
        // Ejecución de código - CRITICAL
        'eval' => [
            'severity' => 'critical',
            'false_positive_risk' => 'low',
            'type' => 'code_execution',
            'token_name' => 'T_EVAL'
        ],
        'assert' => [
            'severity' => 'high',
            'false_positive_risk' => 'medium',
            'type' => 'code_execution',
            'token_name' => 'T_ASSERT'
        ],
        
        // Ejecución de comandos del sistema - CRITICAL/HIGH
        'exec' => [
            'severity' => 'critical',
            'false_positive_risk' => 'low',
            'type' => 'command_execution',
            'token_name' => 'T_EXEC'
        ],
        'system' => [
            'severity' => 'high',
            'false_positive_risk' => 'medium',
            'type' => 'command_execution',
            'token_name' => 'T_SYSTEM'
        ],
        'shell_exec' => [
            'severity' => 'high',
            'false_positive_risk' => 'medium',
            'type' => 'command_execution',
            'token_name' => 'T_SHELL_EXEC'
        ],
        'passthru' => [
            'severity' => 'high',
            'false_positive_risk' => 'medium',
            'type' => 'command_execution',
            'token_name' => 'T_PASSTHRU'
        ],
        'popen' => [
            'severity' => 'high',
            'false_positive_risk' => 'medium',
            'type' => 'command_execution',
            'token_name' => 'T_POPEN'
        ],
        'proc_open' => [
            'severity' => 'high',
            'false_positive_risk' => 'medium',
            'type' => 'command_execution',
            'token_name' => 'T_PROC_OPEN'
        ],
        'proc_get_status' => [
            'severity' => 'medium',
            'false_positive_risk' => 'high',
            'type' => 'command_execution',
            'token_name' => 'T_PROC_GET_STATUS'
        ],
        
        // Inclusión dinámica de archivos - HIGH
        'include' => [
            'severity' => 'medium',
            'false_positive_risk' => 'high',
            'type' => 'file_inclusion',
            'token_name' => 'T_INCLUDE'
        ],
        'include_once' => [
            'severity' => 'medium',
            'false_positive_risk' => 'high',
            'type' => 'file_inclusion',
            'token_name' => 'T_INCLUDE_ONCE'
        ],
        'require' => [
            'severity' => 'medium',
            'false_positive_risk' => 'high',
            'type' => 'file_inclusion',
            'token_name' => 'T_REQUIRE'
        ],
        'require_once' => [
            'severity' => 'medium',
            'false_positive_risk' => 'high',
            'type' => 'file_inclusion',
            'token_name' => 'T_REQUIRE_ONCE'
        ],
        
        // Deserialización insegura - CRITICAL
        'unserialize' => [
            'severity' => 'critical',
            'false_positive_risk' => 'low',
            'type' => 'insecure_deserialization',
            'token_name' => 'T_UNSERIALIZE'
        ],
        
        // Funciones dinámicas - HIGH
        'call_user_func' => [
            'severity' => 'medium',
            'false_positive_risk' => 'high',
            'type' => 'dynamic_call',
            'token_name' => 'T_CALL_USER_FUNC'
        ],
        'call_user_func_array' => [
            'severity' => 'medium',
            'false_positive_risk' => 'high',
            'type' => 'dynamic_call',
            'token_name' => 'T_CALL_USER_FUNC_ARRAY'
        ],
        'create_function' => [
            'severity' => 'high',
            'false_positive_risk' => 'low',
            'type' => 'code_execution',
            'token_name' => 'T_CREATE_FUNCTION'
        ],
        
        // Acceso a archivos - MEDIUM
        'file_get_contents' => [
            'severity' => 'medium',
            'false_positive_risk' => 'high',
            'type' => 'file_access',
            'token_name' => 'T_FILE_GET_CONTENTS'
        ],
        'fopen' => [
            'severity' => 'medium',
            'false_positive_risk' => 'high',
            'type' => 'file_access',
            'token_name' => 'T_FOPEN'
        ],
        'file_put_contents' => [
            'severity' => 'medium',
            'false_positive_risk' => 'high',
            'type' => 'file_access',
            'token_name' => 'T_FILE_PUT_CONTENTS'
        ],
        
        // curl - MEDIUM
        'curl_exec' => [
            'severity' => 'medium',
            'false_positive_risk' => 'high',
            'type' => 'network',
            'token_name' => 'T_CURL_EXEC'
        ],
    ]);
}

/**
 * Obtener lista centralizada de funciones de sanitización
 * 
 * Estas funciones reducen el riesgo cuando se usan antes de funciones peligrosas.
 * 
 * @return array Lista de funciones de sanitización
 */
function aegis_day0_get_sanitizing_functions() {
    return apply_filters('aegis_day0_sanitizing_functions', [
        // WordPress sanitization
        'sanitize_text_field',
        'sanitize_textarea_field',
        'sanitize_key',
        'sanitize_email',
        'sanitize_file_name',
        'sanitize_path',
        'sanitize_title',
        'sanitize_user',
        'wp_kses',
        'wp_kses_post',
        'wp_kses_data',
        'esc_html',
        'esc_attr',
        'esc_url',
        'esc_js',
        'esc_textarea',
        
        // PHP type casting / validation
        'intval',
        'floatval',
        'doubleval',
        'boolval',
        'absint',
        'is_numeric',
        'ctype_digit',
        'filter_var',
        'filter_input',
        
        // WordPress security
        'check_admin_referer',
        'wp_verify_nonce',
        'wp_create_nonce',
        
        // SQL escaping
        'esc_sql',
        'mysqli_real_escape_string',
        'mysqli_escape_string',
        'mysql_real_escape_string',
        'addslashes',
    ]);
}

/**
 * Obtener lista de superglobals de WordPress
 * 
 * @return array Lista de variables superglobales
 */
function aegis_day0_get_superglobals() {
    return apply_filters('aegis_day0_superglobals', [
        '_GET',
        '_POST',
        '_REQUEST',
        '_COOKIE',
        '_SERVER',
        '_FILES',
        '_ENV',
    ]);
}

/**
 * Obtener recomendaciones para funciones peligrosas
 * 
 * @param string $function_name Nombre de la función
 * @return string Recomendación de seguridad
 */
function aegis_day0_get_recommendation($function_name) {
    $recommendations = apply_filters('aegis_day0_recommendations', [
        'eval' => __('NUNCA usar eval() con input de usuario. Considerar alternativas seguras.', 'aegis-day0'),
        'exec' => __('Usar escapeshellarg() para sanitizar argumentos. Validar whitelist de comandos.', 'aegis-day0'),
        'system' => __('Evitar cuando sea posible. Usar funciones específicas de WordPress.', 'aegis-day0'),
        'shell_exec' => __('Sanitizar con escapeshellarg(). Considerar wp_safe_remote_get() para HTTP.', 'aegis-day0'),
        'passthru' => __('Validar exhaustivamente los argumentos. Usar output buffering con precaución.', 'aegis-day0'),
        'popen' => __('Cerrar siempre el handle con pclose(). Validar comandos.', 'aegis-day0'),
        'proc_open' => __('Usar solo con comandos predefinidos. Nunca con input directo.', 'aegis-day0'),
        'unserialize' => __('Reemplazar con json_decode() cuando sea posible. Usar allowed_classes.', 'aegis-day0'),
        'assert' => __('No usar assert() con expresiones dinámicas en producción.', 'aegis-day0'),
        'create_function' => __('Obsoleto desde PHP 7.2. Usar funciones anónimas.', 'aegis-day0'),
        'file_get_contents' => __('Validar URLs con wp_http_validate_url(). Usar filtros de contexto.', 'aegis-day0'),
        'fopen' => __('Validar rutas con realpath(). Restringir a directorios permitidos.', 'aegis-day0'),
        'curl_exec' => __('Validar URLs con wp_http_validate_url(). Usar timeouts apropiados.', 'aegis-day0'),
        'call_user_func' => __('Validar que el callback apunte a funciones seguras.', 'aegis-day0'),
        'call_user_func_array' => __('Validar callbacks. Evitar input de usuario directo.', 'aegis-day0'),
        'include' => __('Usar rutas absolutas con realpath(). Implementar whitelist.', 'aegis-day0'),
        'include_once' => __('Usar rutas absolutas con realpath(). Implementar whitelist.', 'aegis-day0'),
        'require' => __('Usar rutas absolutas con realpath(). Implementar whitelist.', 'aegis-day0'),
        'require_once' => __('Usar rutas absolutas con realpath(). Implementar whitelist.', 'aegis-day0'),
    ]);
    
    $func_lower = strtolower($function_name);
    return isset($recommendations[$func_lower]) 
        ? $recommendations[$func_lower] 
        : __('Verificar documentación y mejores prácticas.', 'aegis-day0');
}
