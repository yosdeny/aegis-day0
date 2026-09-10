<?php
/**
 * Aegis Day0 - Advanced Token-Based Static Analyzer
 * 
 * Analizador estático avanzado usando token_get_all() nativo de PHP
 * para detectar patrones de vulnerabilidad con menor tasa de falsos positivos
 * 
 * @package Aegis_Day0
 * @since 0.3
 */

if (!defined('ABSPATH')) {
    exit;
}

class Aegis_Token_Analyzer {
    
    /**
     * Tokens peligrosos y sus contextos
     */
    private $dangerous_tokens = [
        'T_EVAL' => ['severity' => 'critical', 'false_positive_risk' => 'low'],
        'T_EXEC' => ['severity' => 'critical', 'false_positive_risk' => 'low'],
        'T_SYSTEM' => ['severity' => 'high', 'false_positive_risk' => 'medium'],
        'T_SHELL_EXEC' => ['severity' => 'high', 'false_positive_risk' => 'medium'],
        'T_PASSTHRU' => ['severity' => 'high', 'false_positive_risk' => 'medium'],
        'T_POPEN' => ['severity' => 'high', 'false_positive_risk' => 'medium'],
        'T_PROC_OPEN' => ['severity' => 'high', 'false_positive_risk' => 'medium'],
        'T_CURL_EXEC' => ['severity' => 'medium', 'false_positive_risk' => 'high'],
        'T_FILE_GET_CONTENTS' => ['severity' => 'medium', 'false_positive_risk' => 'high'],
        'T_FOPEN' => ['severity' => 'medium', 'false_positive_risk' => 'high'],
        'T_UNSERIALIZE' => ['severity' => 'critical', 'false_positive_risk' => 'low'],
        'T_ASSERT' => ['severity' => 'high', 'false_positive_risk' => 'medium'],
        'T_CREATE_FUNCTION' => ['severity' => 'high', 'false_positive_risk' => 'low'],
        'T_CALL_USER_FUNC' => ['severity' => 'medium', 'false_positive_risk' => 'high'],
        'T_CALL_USER_FUNC_ARRAY' => ['severity' => 'medium', 'false_positive_risk' => 'high'],
        'T_INCLUDE' => ['severity' => 'medium', 'false_positive_risk' => 'high'],
        'T_INCLUDE_ONCE' => ['severity' => 'medium', 'false_positive_risk' => 'high'],
        'T_REQUIRE' => ['severity' => 'medium', 'false_positive_risk' => 'high'],
        'T_REQUIRE_ONCE' => ['severity' => 'medium', 'false_positive_risk' => 'high'],
    ];
    
    /**
     * Funciones sanitizadoras que reducen el riesgo
     */
    private $sanitizing_functions = [
        'sanitize_text_field',
        'esc_html',
        'esc_attr',
        'esc_url',
        'wp_kses',
        'wp_kses_post',
        'intval',
        'absint',
        'floatval',
        'wp_parse_args',
        'sanitize_key',
        'sanitize_email',
        'sanitize_file_name',
        'check_admin_referer',
        'wp_verify_nonce'
    ];
    
    /**
     * Analiza un archivo PHP usando tokens
     * 
     * @param string $file_path Ruta del archivo a analizar
     * @return array Alertas encontradas
     */
    public function analyze_file($file_path) {
        $alerts = [];
        
        if (!file_exists($file_path) || !is_readable($file_path)) {
            return $alerts;
        }
        
        $content = file_get_contents($file_path);
        if (empty($content)) {
            return $alerts;
        }
        
        $tokens = token_get_all($content);
        $token_count = count($tokens);
        
        // Estado del analizador
        $in_comment = false;
        $in_string = false;
        $current_function = null;
        $function_stack = [];
        $variable_sources = [];
        $line_number = 1;
        
        for ($i = 0; $i < $token_count; $i++) {
            $token = $tokens[$i];
            
            // Manejar tokens simples (strings de un carácter)
            if (is_string($token)) {
                if ($token === '{') {
                    if ($current_function) {
                        $function_stack[] = $current_function;
                    }
                } elseif ($token === '}') {
                    if (!empty($function_stack)) {
                        array_pop($function_stack);
                        $current_function = end($function_stack) ?: null;
                    }
                }
                continue;
            }
            
            list($token_id, $token_value, $token_line) = $token;
            
            // Actualizar número de línea
            $line_number = $token_line;
            
            // Ignorar comentarios y docblocks
            if (in_array($token_id, [T_COMMENT, T_DOC_COMMENT])) {
                $in_comment = true;
                continue;
            }
            
            if ($token_id === T_WHITESPACE) {
                continue;
            }
            
            // Detectar definición de funciones
            if ($token_id === T_FUNCTION) {
                if (isset($tokens[$i + 2]) && is_array($tokens[$i + 2])) {
                    $current_function = $tokens[$i + 2][1];
                }
                continue;
            }
            
            // Rastrear origen de variables ($_GET, $_POST, etc.)
            if ($token_id === T_VARIABLE) {
                $var_name = substr($token_value, 1); // Quitar el $
                
                // Verificar si es variable superglobal
                if (in_array($var_name, ['GET', 'POST', 'REQUEST', 'COOKIE', 'SERVER', 'FILES'])) {
                    // Buscar el nombre completo de la variable
                    if (isset($tokens[$i + 1]) && $tokens[$i + 1] === '[') {
                        if (isset($tokens[$i + 2]) && is_array($tokens[$i + 2])) {
                            $key = trim($tokens[$i + 2][1], "'\"");
                            $variable_sources["\${$var_name}['{$key}']"] = 'user_input';
                        }
                    }
                }
                continue;
            }
            
            // Detectar funciones peligrosas
            if ($token_id === T_STRING) {
                $function_name = strtolower($token_value);
                $token_name = 'T_' . strtoupper($function_name);
                
                if (!isset($this->dangerous_tokens[$token_name])) {
                    continue;
                }
                
                $rule = $this->dangerous_tokens[$token_name];
                
                // Verificar contexto: ¿está en un comentario?
                if ($in_comment) {
                    continue;
                }
                
                // Verificar si hay sanitización previa
                $is_sanitized = $this->check_sanitization($tokens, $i, $function_name);
                
                // Verificar si usa input de usuario directo
                $uses_user_input = $this->check_user_input($tokens, $i, $variable_sources);
                
                // Calcular severidad ajustada
                $adjusted_severity = $rule['severity'];
                $false_positive_risk = $rule['false_positive_risk'];
                
                if ($is_sanitized) {
                    $adjusted_severity = 'low';
                    $false_positive_risk = 'high';
                } elseif (!$uses_user_input) {
                    $adjusted_severity = 'medium';
                    $false_positive_risk = 'medium';
                }
                
                // Generar alerta solo si es relevante
                if ($adjusted_severity !== 'low' || $uses_user_input) {
                    $alerts[] = [
                        'type' => 'token_analysis',
                        'function' => $function_name,
                        'file' => $file_path,
                        'line' => $token_line,
                        'severity' => $adjusted_severity,
                        'false_positive_risk' => $false_positive_risk,
                        'description' => sprintf(
                            __('Función peligrosa detectada: %s. %s', 'aegis-day0'),
                            $function_name,
                            $uses_user_input ? __('Usa input de usuario sin validación aparente.', 'aegis-day0') : __('Verificar contexto de uso.', 'aegis-day0')
                        ),
                        'context' => $this->get_code_context($content, $token_line),
                        'recommendation' => $this->get_recommendation($function_name)
                    ];
                }
            }
        }
        
        return $alerts;
    }
    
    /**
     * Verifica si hay funciones sanitizadoras cercanas
     */
    private function check_sanitization($tokens, $current_index, $dangerous_function) {
        // Buscar hacia atrás (últimos 20 tokens)
        $search_range = min(20, $current_index);
        
        for ($i = $current_index - 1; $i > $current_index - $search_range && $i >= 0; $i--) {
            if (!is_array($tokens[$i])) {
                continue;
            }
            
            if ($tokens[$i][0] === T_STRING) {
                $func_name = strtolower($tokens[$i][1]);
                
                if (in_array($func_name, $this->sanitizing_functions)) {
                    return true;
                }
                
                // Si encontramos otra función peligrosa antes, detener búsqueda
                if (strpos($func_name, 'exec') !== false || strpos($func_name, 'eval') !== false) {
                    break;
                }
            }
        }
        
        return false;
    }
    
    /**
     * Verifica si la función usa input de usuario
     */
    private function check_user_input($tokens, $current_index, $variable_sources) {
        // Buscar hacia adelante para encontrar parámetros
        $parenthesis_level = 0;
        $found_opening = false;
        
        for ($i = $current_index + 1; $i < count($tokens) && $i < $current_index + 50; $i++) {
            $token = $tokens[$i];
            
            if (is_string($token)) {
                if ($token === '(') {
                    $found_opening = true;
                    $parenthesis_level++;
                } elseif ($token === ')') {
                    $parenthesis_level--;
                    if ($parenthesis_level === 0) {
                        break;
                    }
                } elseif ($token === ',' && $parenthesis_level === 1) {
                    // Separador de parámetros
                }
                continue;
            }
            
            if ($token[0] === T_VARIABLE) {
                $var_name = substr($token[1], 1);
                if (in_array($var_name, ['GET', 'POST', 'REQUEST', 'COOKIE', 'SERVER', 'FILES'])) {
                    return true;
                }
            }
        }
        
        return false;
    }
    
    /**
     * Obtiene contexto del código (línea específica)
     */
    private function get_code_context($content, $line_number) {
        $lines = explode("\n", $content);
        $index = $line_number - 1;
        
        if (!isset($lines[$index])) {
            return '';
        }
        
        $context_line = trim($lines[$index]);
        
        // Limitar longitud
        if (strlen($context_line) > 150) {
            $context_line = substr($context_line, 0, 147) . '...';
        }
        
        return $context_line;
    }
    
    /**
     * Obtiene recomendación para una función específica
     */
    private function get_recommendation($function_name) {
        $recommendations = [
            'eval' => __('Nunca usar eval() con input de usuario. Considerar alternativas seguras.', 'aegis-day0'),
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
        ];
        
        return isset($recommendations[$function_name]) 
            ? $recommendations[$function_name] 
            : __('Verificar documentación y mejores prácticas.', 'aegis-day0');
    }
    
    /**
     * Analiza múltiples archivos
     * 
     * @param array $files Lista de rutas de archivos
     * @return array Resultados consolidados
     */
    public function analyze_files($files) {
        $all_alerts = [];
        $stats = [
            'total_files' => count($files),
            'scanned_files' => 0,
            'total_alerts' => 0,
            'by_severity' => ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0]
        ];
        
        foreach ($files as $file) {
            if (!file_exists($file)) {
                continue;
            }
            
            $stats['scanned_files']++;
            $alerts = $this->analyze_file($file);
            
            foreach ($alerts as $alert) {
                $severity = strtolower($alert['severity']);
                if (isset($stats['by_severity'][$severity])) {
                    $stats['by_severity'][$severity]++;
                }
            }
            
            $stats['total_alerts'] += count($alerts);
            $all_alerts = array_merge($all_alerts, $alerts);
        }
        
        return [
            'alerts' => $all_alerts,
            'stats' => $stats
        ];
    }
}
