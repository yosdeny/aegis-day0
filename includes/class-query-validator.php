<?php
/**
 * Clase para detectar y reportar malas prácticas en wpdb::prepare()
 * 
 * Esta clase ayuda a identificar consultas SQL mal formadas antes de que
 * WordPress genere un aviso genérico en los logs.
 * 
 * @package GloriaRiMercado
 * @since 1.0.0
 */

if (!defined('ABSPATH')) {
    exit; // Salida directa si se accede directamente
}

class GRM_Query_Validator {

    /**
     * Bandera para evitar bucles infinitos si esta clase usa BD internamente
     */
    private static $is_validating = false;

    /**
     * Inicializar el validador.
     * Debe llamarse en el hook 'plugins_loaded' o similar.
     */
    public static function init() {
        // Solo activar en modo depuración para no afectar rendimiento en producción
        if (!defined('WP_DEBUG') || !WP_DEBUG) {
            return;
        }

        // Opción A: Envolver globalmente (Requiere reemplazar $wpdb o usar output buffering en logs)
        // Opción B: Proporcionar un método helper que los desarrolladores DEBEN usar.
        
        // Implementaremos la Opción B (Helper) + Un filtro para capturar errores de WordPress si es posible
        add_action('wp_loaded', array(__CLASS__, 'maybe_run_self_test'));
    }

    /**
     * Método Helper Recomendado: Reemplazar $wpdb->prepare() por este en el código del plugin.
     * 
     * Uso:
     *   MAL: $wpdb->prepare("SELECT * FROM table WHERE id = %d", $id);
     *   BIEN: GRM_Query_Validator::safe_prepare($wpdb, "SELECT * FROM table WHERE id = %d", $id);
     * 
     * @param wpdb $wpdb Instancia global de wpdb.
     * @param string $query La consulta SQL con marcadores.
     * @param mixed ...$args Los argumentos a reemplazar.
     * @return string|null La consulta preparada o null si falla la validación.
     */
    public static function safe_prepare($wpdb, $query, ...$args) {
        if (self::$is_validating) {
            return $wpdb->prepare($query, ...$args);
        }

        self::$is_validating = true;

        // 1. Contar marcadores en la query
        // Buscamos %s, %d, %f, pero ignoramos %% (escapados)
        $pattern = '/%(?:%|[^%])/';
        preg_match_all($pattern, $query, $matches);
        
        $total_markers = 0;
        foreach ($matches[0] as $match) {
            if ($match !== '%%') {
                $total_markers++;
            }
        }

        $total_args = count($args);

        // 2. Validar coincidencia
        if ($total_markers !== $total_args) {
            self::log_error($query, $total_markers, $total_args, $args);
            
            // En modo estricto (desarrollo), podemos forzar un error visible
            if (defined('GRM_STRICT_DB_CHECK') && GRM_STRICT_DB_CHECK) {
                // Esto detendrá la ejecución y mostrará el stack trace exacto
                trigger_error(
                    sprintf(
                        "GRM DB Error: Marcadores (%d) != Argumentos (%d). Query: %s",
                        $total_markers,
                        $total_args,
                        substr($query, 0, 100)
                    ),
                    E_USER_ERROR
                );
            }
            
            // Retornar null o intentar preparar de todos modos (dejar que WP falle)
            // Recomendación: Retornar null para evitar queries peligrosas
            self::$is_validating = false;
            return null; 
        }

        self::$is_validating = false;
        return $wpdb->prepare($query, ...$args);
    }

    /**
     * Registrar el error con información detallada de quién llamó.
     */
    private static function log_error($query, $markers_count, $args_count, $args) {
        $backtrace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 6);
        
        // Buscar el primer llamado que NO sea esta clase ni funciones internas de WP
        $caller_info = 'Desconocido';
        foreach ($backtrace as $index => $trace) {
            if (isset($trace['class']) && strpos($trace['class'], 'GRM_Query_Validator') !== false) {
                continue;
            }
            if (isset($trace['file'])) {
                $caller_info = sprintf(
                    "Llamado desde: %s en la línea %d",
                    str_replace(ABSPATH, '', $trace['file']),
                    $trace['line']
                );
                
                // Si hay una función, la incluimos
                if (isset($trace['function'])) {
                    $caller_info .= sprintf(" (Función: %s)", $trace['function']);
                }
                break;
            }
        }

        $error_msg = sprintf(
            "[GRM VALIDATOR] ERROR DE PREPARACIÓN DE CONSULTA DETECTADO:\n" .
            "- Archivo/Origen: %s\n" .
            "- Consultas: %s\n" .
            "- Marcadores encontrados: %d\n" .
            "- Argumentos pasados: %d\n" .
            "- Argumentos recibidos: %s\n" .
            "--------------------------------------------------\n",
            $caller_info,
            $query,
            $markers_count,
            $args_count,
            json_encode($args)
        );

        error_log($error_msg);
    }

    /**
     * Auto-prueba opcional para verificar que el validador funciona.
     */
    public static function maybe_run_self_test() {
        if (!defined('GRM_RUN_VALIDATOR_TEST') || !GRM_RUN_VALIDATOR_TEST) {
            return;
        }
        
        global $wpdb;
        error_log("[GRM VALIDATOR] Iniciando auto-prueba...");
        
        // Caso correcto
        self::safe_prepare($wpdb, "SELECT * FROM {$wpdb->posts} WHERE ID = %d", 1);
        
        // Caso incorrecto (generará log)
        self::safe_prepare($wpdb, "SELECT * FROM {$wpdb->posts} WHERE ID = %d AND status = %s", 1);
        
        error_log("[GRM VALIDATOR] Auto-prueba finalizada.");
    }
}

// Iniciar si estamos en debug
if (defined('WP_DEBUG') && WP_DEBUG) {
    GRM_Query_Validator::init();
}
