<?php
/**
 * Dashboard y Administración del Plugin Aegis Day0
 * 
 * @package AegisDay0
 */

if (!defined('ABSPATH')) exit;

/**
 * Registra el menú principal y submenús
 */
function aegis_day0_admin_menu() {
    // Menú Principal
    add_menu_page(
        'Aegis Day0',
        'Aegis Day0',
        'manage_options',
        'aegis-day0',
        'aegis_day0_dashboard_page',
        'dashicons-shield-alt',
        99
    );

    // Submenú 1: Dashboard (Vulnerabilidades Activas) - Página por defecto
    add_submenu_page(
        'aegis-day0',
        'Dashboard - Vulnerabilidades',
        'Dashboard',
        'manage_options',
        'aegis-day0',
        'aegis_day0_dashboard_page'
    );

    // Submenú 2: Logs (Histórico de Acciones)
    add_submenu_page(
        'aegis-day0',
        'Historial de Acciones',
        'Logs',
        'manage_options',
        'aegis-day0-logs',
        'aegis_day0_logs_page'
    );

    // Submenú 3: Configuración
    add_submenu_page(
        'aegis-day0',
        'Configuración',
        'Config',
        'manage_options',
        'aegis-day0-config',
        'aegis_day0_config_page'
    );
}
add_action('admin_menu', 'aegis_day0_admin_menu');

/**
 * Maneja la acción de limpiar logs
 */
function aegis_day0_handle_clear_logs() {
    if (isset($_POST['aegis_clear_logs']) && check_admin_referer('aegis_clear_logs_action')) {
        if (current_user_can('manage_options')) {
            delete_option('aegis_day0_logs');
            wp_redirect(admin_url('admin.php?page=aegis-day0-logs&cleared=1'));
            exit;
        }
    }
}
add_action('admin_init', 'aegis_day0_handle_clear_logs');

/**
 * Maneja la acción de escaneo forzado desde el dashboard
 */
function aegis_day0_handle_force_scan() {
    if (isset($_POST['force_scan']) && check_admin_referer('aegis_force_scan_action')) {
        if (current_user_can('manage_options')) {
            delete_transient('aegis_day0_last_scan');
            $scanner = new Aegis_Day0_Scanner();
            $scanner->run_checks();
            echo '<div class="notice notice-success is-dismissible"><p>Escaneo forzado completado con exito.</p></div>';
        }
    }
}
add_action('admin_init', 'aegis_day0_handle_force_scan');

/**
 * Maneja la acción de limpiar alertas y realizar escaneo limpio
 */
function aegis_day0_handle_clean_scan() {
    if (isset($_POST['clean_scan']) && check_admin_referer('aegis_clean_scan_action')) {
        if (current_user_can('manage_options')) {
            // Limpiar alertas almacenadas
            delete_option('aegis_day0_alerts');
            delete_option('aegis_day0_notified_alerts');
            delete_transient('aegis_day0_last_scan');
            
            // Ejecutar nuevo escaneo limpio
            $scanner = new Aegis_Day0_Scanner();
            $scanner->run_checks();
            
            echo '<div class="notice notice-success is-dismissible"><p>🧹 Escaneo limpio completado. Se eliminaron los falsos positivos anteriores.</p></div>';
        }
    }
}
add_action('admin_init', 'aegis_day0_handle_clean_scan');

/**
 * Renderiza la pagina del Dashboard
 */
function aegis_day0_dashboard_page() {
    $alerts = get_option('aegis_day0_alerts', []);
    ?>
    <div class="wrap aegis-day0-dashboard">
        <h1 style="margin-bottom: 20px;">🛡️ Dashboard de Seguridad</h1>
        
        <!-- Botones de Acción -->
        <form method="post" style="margin-bottom: 30px; background: #f0f0f1; padding: 20px; border-radius: 4px;">
            <?php wp_nonce_field('aegis_force_scan_action'); ?>
            <button type="submit" name="force_scan" class="button button-primary button-large">
                🔄 Ejecutar Escaneo Ahora
            </button>
            <span style="margin-left: 10px; color: #666;">Escanea todos los plugins en busca de vulnerabilidades 0-day</span>
        </form>
        
        <form method="post" style="margin-bottom: 30px; background: #e8f4f8; padding: 20px; border-radius: 4px; border-left: 4px solid #2271b1;">
            <?php wp_nonce_field('aegis_clean_scan_action'); ?>
            <button type="submit" name="clean_scan" class="button button-secondary button-large" onclick="return confirm('⚠️ Esto eliminará todas las alertas almacenadas y realizará un escaneo completamente limpio.\\n\\n¿Estás seguro?');">
                🧹 Limpiar Alertas y Re-escanear
            </button>
            <span style="margin-left: 10px; color: #666;">Elimina falsos positivos previos y ejecuta un escaneo desde cero con las nuevas reglas</span>
        </form>

        <!-- Tabla de Vulnerabilidades -->
        <h2>⚠️ Vulnerabilidades Detectadas</h2>
        <?php if (empty($alerts)) : ?>
            <div class="notice notice-success inline"><p>✅ No se detectaron vulnerabilidades activas en este momento.</p></div>
        <?php else : ?>
            <div class="aegis-day0-logs-table-wrapper">
                <table class="wp-list-table widefat fixed striped">
                    <thead>
                        <tr>
                            <th style="width: 20%;">Plugin</th>
                            <th style="width: 35%;">Tipo</th>
                            <th style="width: 10%;">Severidad</th>
                            <th style="width: 15%;">Fuente</th>
                            <th style="width: 20%;">Riesgo Falso Positivo</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($alerts as $alert) : 
                            $fp_risk = isset($alert['false_positive_risk']) ? $alert['false_positive_risk'] : 'Desconocido';
                            $icon = ($fp_risk === 'Alto') ? '⚠️' : (($fp_risk === 'Medio') ? '◐' : '✅');
                            $severity_color = ($alert['severity'] === 'Critical') ? 'red' : 'orange';
                        ?>
                        <tr>
                            <td><strong><?php echo esc_html($alert['plugin']); ?></strong></td>
                            <td><?php echo esc_html($alert['type']); ?></td>
                            <td><span style="color: <?php echo $severity_color; ?>; font-weight: bold;"><?php echo esc_html($alert['severity']); ?></span></td>
                            <td><?php echo esc_html($alert['source']); ?></td>
                            <td><?php echo $icon . ' ' . esc_html($fp_risk); ?></td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php endif; ?>
    </div>
    <?php
}

/**
 * Renderiza la página de Logs (Histórico)
 */
function aegis_day0_logs_page() {
    $logs = get_option('aegis_day0_logs', []);
    
    // Paginación simple
    $per_page = 50;
    $current_page = isset($_GET['paged']) ? max(1, intval($_GET['paged'])) : 1;
    $total_logs = count($logs);
    $total_pages = ceil($total_logs / $per_page);
    $offset = ($current_page - 1) * $per_page;
    
    // Invertir orden para mostrar más recientes primero, luego aplicar paginación
    $reversed_logs = array_reverse($logs);
    $paged_logs = array_slice($reversed_logs, $offset, $per_page);
    ?>
    <div class="wrap aegis-day0-dashboard">
        <h1 style="margin-bottom: 20px;">📜 Historial de Acciones y Escaneos</h1>
        
        <?php if (isset($_GET['cleared'])) : ?>
            <div class="notice notice-success is-dismissible"><p>🗑️ Historial limpiado correctamente.</p></div>
        <?php endif; ?>

        <!-- Botón Limpiar Todo -->
        <form method="post" style="margin-bottom: 20px;" onsubmit="return confirm('⚠️ ¿Estás SEGURO de borrar TODO el historial?\n\nEsta acción no se puede deshacer.');">
            <?php wp_nonce_field('aegis_clear_logs_action'); ?>
            <button type="submit" name="aegis_clear_logs" class="button button-link-delete" style="border-color: #d63638; color: #d63638;">
                🗑️ Limpiar Todo el Historial
            </button>
        </form>

        <!-- Botón Exportar Logs -->
        <form method="post" action="<?php echo admin_url('admin-post.php'); ?>" style="margin-bottom: 20px; display: inline-block;">
            <?php wp_nonce_field('aegis_export_logs_action'); ?>
            <input type="hidden" name="action" value="aegis_export_logs">
            <label for="export_format">Exportar:</label>
            <select name="format" id="export_format" style="margin: 0 10px;">
                <option value="csv">CSV</option>
                <option value="json">JSON</option>
            </select>
            <button type="submit" class="button button-secondary">📥 Descargar Logs</button>
        </form>

        <?php if (empty($logs)) : ?>
            <div class="notice notice-info"><p>ℹ️ No hay registros históricos disponibles.</p></div>
        <?php else : ?>
            <div class="aegis-day0-logs-table-wrapper">
                <table class="wp-list-table widefat fixed striped">
                    <thead>
                        <tr>
                            <th style="width: 15%;">Fecha</th>
                            <th style="width: 15%;">Plugin</th>
                            <th style="width: 25%;">Tipo</th>
                            <th style="width: 10%;">Severidad</th>
                            <th style="width: 10%;">Fuente</th>
                            <th style="width: 25%;">Acción</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($paged_logs as $log) : ?>
                        <tr>
                            <td><?php echo esc_html($log['date']); ?></td>
                            <td><?php echo esc_html($log['plugin']); ?></td>
                            <td><?php echo esc_html($log['type']); ?></td>
                            <td><?php echo esc_html($log['severity']); ?></td>
                            <td><?php echo esc_html($log['source']); ?></td>
                            <td style="max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="<?php echo esc_attr($log['action']); ?>">
                                <?php echo esc_html($log['action']); ?>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>

            <!-- Paginación -->
            <?php if ($total_pages > 1) : ?>
                <div class="tablenav">
                    <div class="tablenav-pages">
                        <span class="displaying-num"><?php echo number_format($total_logs); ?> elementos en total</span>
                        <?php
                        echo paginate_links([
                            'base' => add_query_arg('paged', '%#%'),
                            'format' => '',
                            'prev_text' => '&laquo; Anterior',
                            'next_text' => 'Siguiente &raquo;',
                            'total' => $total_pages,
                            'current' => $current_page,
                            'mid_size' => 2
                        ]);
                        ?>
                    </div>
                </div>
            <?php endif; ?>
        <?php endif; ?>
    </div>
    <?php
}

/**
 * Renderiza la página de Configuración
 */
function aegis_day0_config_page() {
    settings_errors();
    ?>
    <div class="wrap aegis-day0-dashboard">
        <h1 style="margin-bottom: 20px;">⚙️ Configuración de Aegis Day0</h1>
        <form method="post" action="options.php" style="background: #fff; padding: 20px; border: 1px solid #ccd0d4; max-width: 800px;">
            <?php
            settings_fields('aegis_day0_settings_group');
            do_settings_sections('aegis_day0_settings_page');
            submit_button('Guardar Configuración', 'primary', 'submit', true, ['style' => 'margin-top: 20px;']);
            ?>
        </form>
    </div>
    <?php
}

// --- Callbacks de los campos de configuración ---
// Las funciones callback de configuración están definidas en aegis-day0.php

/**
 * Maneja la exportación de logs
 */
function aegis_day0_handle_export_logs() {
    if (!current_user_can('manage_options')) {
        wp_die('No tienes permisos para realizar esta acción.');
    }
    
    check_admin_referer('aegis_export_logs_action');
    
    $format = isset($_POST['format']) ? sanitize_text_field($_POST['format']) : 'csv';
    $export = Aegis_Day0_Logger::export_logs($format);
    
    if (empty($export)) {
        wp_die('No hay logs para exportar.');
    }
    
    $filename = 'aegis-day0-logs-' . current_time('Y-m-d-H-i-s') . '.' . ($format === 'json' ? 'json' : 'csv');
    
    header('Content-Type: ' . ($format === 'json' ? 'application/json' : 'text/csv'));
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    header('Pragma: no-cache');
    header('Expires: 0');
    
    echo $export;
    exit;
}
add_action('admin_post_aegis_export_logs', 'aegis_day0_handle_export_logs');
