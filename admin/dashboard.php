<?php
/**
 * Registro del menú principal y submenús
 */
function aegis_day0_admin_menu() {
    if ( ! current_user_can('manage_options') ) {
        return;
    }
    
    // Menú principal - Dashboard
    add_menu_page(
        __('Aegis Day0', 'aegis-day0'),
        __('Aegis Day0', 'aegis-day0'),
        'manage_options',
        'aegis-day0',
        'aegis_day0_dashboard',
        'dashicons-shield-alt',
        80
    );
    
    // Submenú - Dashboard (página por defecto)
    add_submenu_page(
        'aegis-day0',
        __('Dashboard', 'aegis-day0'),
        __('Dashboard', 'aegis-day0'),
        'manage_options',
        'aegis-day0',
        'aegis_day0_dashboard'
    );
    
    // Submenú - Configuración
    add_submenu_page(
        'aegis-day0',
        __('Configuración', 'aegis-day0'),
        __('Config', 'aegis-day0'),
        'manage_options',
        'aegis-day0-config',
        'aegis_day0_config'
    );
    
    // Submenú - Logs (Histórico)
    add_submenu_page(
        'aegis-day0',
        __('Historial de Acciones', 'aegis-day0'),
        __('Logs', 'aegis-day0'),
        'manage_options',
        'aegis-day0-logs',
        'aegis_day0_logs_page'
    );
}
add_action('admin_menu', 'aegis_day0_admin_menu');

/**
 * Manejo de limpieza de logs
 */
function aegis_day0_handle_clear_logs() {
    if (isset($_POST['aegis_clear_logs']) && current_user_can('manage_options')) {
        if (!isset($_POST['aegis_clear_logs_nonce']) || !wp_verify_nonce($_POST['aegis_clear_logs_nonce'], 'aegis_clear_logs_action')) {
            wp_die(__('Security check failed', 'aegis-day0'));
        }
        delete_option('aegis_day0_scan_logs');
        wp_redirect(admin_url('admin.php?page=aegis-day0-logs&cleared=1'));
        exit;
    }
}
add_action('admin_init', 'aegis_day0_handle_clear_logs');

/**
 * Página dedicada para Logs
 */
function aegis_day0_logs_page() {
    $logs = Aegis_Day0_Logger::get_logs();
    $total_logs = count($logs);
    $per_page = 50;
    $current_page = isset($_GET['paged']) ? max(1, intval($_GET['paged'])) : 1;
    $total_pages = ceil($total_logs / $per_page);
    $offset = ($current_page - 1) * $per_page;
    $paged_logs = array_slice(array_reverse($logs), $offset, $per_page);
    ?>
    <div class="wrap aegis-day0-logs">
        <h1><?php echo esc_html__('📜 Historial de Acciones y Escaneos', 'aegis-day0'); ?></h1>
        
        <?php if (isset($_GET['cleared'])) : ?>
            <div class="notice notice-success is-dismissible">
                <p><?php echo esc_html__('✅ Historial limpiado correctamente.', 'aegis-day0'); ?></p>
            </div>
        <?php endif; ?>
        
        <!-- Botón de limpiar -->
        <div style="margin: 20px 0;">
            <form method="post" onsubmit="return confirm('<?php echo esc_js(__('¿Estás seguro de borrar TODO el historial? Esta acción no se puede deshacer.', 'aegis-day0')); ?>');">
                <?php wp_nonce_field('aegis_clear_logs_action', 'aegis_clear_logs_nonce'); ?>
                <button type="submit" name="aegis_clear_logs" class="button button-link-delete">
                    🗑️ <?php echo esc_html__('Limpiar Todo el Historial', 'aegis-day0'); ?>
                </button>
            </form>
        </div>
        
        <?php if (empty($logs)) : ?>
            <div class="notice notice-info">
                <p><?php echo esc_html__('No hay registros históricos.', 'aegis-day0'); ?></p>
            </div>
        <?php else : ?>
            <table class="widefat fixed striped">
                <thead>
                    <tr>
                        <th><?php echo esc_html__('Fecha', 'aegis-day0'); ?></th>
                        <th><?php echo esc_html__('Plugin', 'aegis-day0'); ?></th>
                        <th><?php echo esc_html__('Tipo', 'aegis-day0'); ?></th>
                        <th><?php echo esc_html__('Severidad', 'aegis-day0'); ?></th>
                        <th><?php echo esc_html__('Fuente', 'aegis-day0'); ?></th>
                        <th><?php echo esc_html__('Detalle', 'aegis-day0'); ?></th>
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
                        <td style="max-width: 300px; overflow: hidden; text-overflow: ellipsis;">
                            <?php echo esc_html($log['action']); ?>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            
            <!-- Paginación -->
            <?php if ($total_pages > 1) : ?>
                <div class="tablenav">
                    <div class="tablenav-pages">
                        <span class="displaying-num">
                            <?php printf(esc_html__('%d elementos', 'aegis-day0'), $total_logs); ?>
                        </span>
                        <?php
                        echo paginate_links([
                            'base' => add_query_arg('paged', '%#%'),
                            'format' => '',
                            'prev_text' => '&laquo;',
                            'next_text' => '&raquo;',
                            'total' => $total_pages,
                            'current' => $current_page
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
 * Dashboard - Vista de vulnerabilidades activas
 */
function aegis_day0_dashboard() {
    // Verify nonce for export actions
    if (isset($_POST['aegis_day0_export']) && current_user_can('manage_options')) {
        if (!isset($_POST['aegis_day0_export_nonce']) || !wp_verify_nonce($_POST['aegis_day0_export_nonce'], 'aegis_day0_export_action')) {
            wp_die(__('Security check failed', 'aegis-day0'));
        }
        
        $format = sanitize_text_field($_POST['aegis_day0_export']);
        $output = Aegis_Day0_Logger::export_logs($format);
        
        if (!empty($output)) {
            $filename = 'aegis-day0-logs-' . date('Y-m-d-H-i-s') . '.' . $format;
            header('Content-Type: text/' . ($format === 'json' ? 'json' : 'csv'));
            header('Content-Disposition: attachment; filename="' . $filename . '"');
            echo $output;
            exit;
        }
    }
    
    // Generate nonce for export form
    $export_nonce = wp_create_nonce('aegis_day0_export_action');
    
    // Nonce for manual scan
    $scan_nonce = wp_create_nonce('aegis_day0_manual_scan');
    
    // Handle manual scan request
    $scan_message = '';
    if (isset($_POST['aegis_day0_manual_scan']) && current_user_can('manage_options')) {
        if (isset($_POST['aegis_day0_scan_nonce']) && wp_verify_nonce($_POST['aegis_day0_scan_nonce'], 'aegis_day0_manual_scan')) {
            if (function_exists('aegis_day0_force_scan')) {
                aegis_day0_force_scan();
                $scan_message = '<div class="notice notice-success"><p>' . esc_html__('✅ Escaneo completado exitosamente', 'aegis-day0') . '</p></div>';
            }
        } else {
            $scan_message = '<div class="notice notice-error"><p>' . esc_html__('❌ Error de seguridad en el escaneo', 'aegis-day0') . '</p></div>';
        }
    }
    ?>
    <div class="wrap aegis-day0-dashboard">
        <?php echo $scan_message; ?>
        <h1><?php echo esc_html__('🛡️ Aegis Day0 - Dashboard', 'aegis-day0'); ?></h1>
        
        <!-- Manual Scan Button -->
        <div style="margin: 20px 0;">
            <form method="post">
                <?php wp_nonce_field('aegis_day0_manual_scan', 'aegis_day0_scan_nonce'); ?>
                <button type="submit" name="aegis_day0_manual_scan" class="button button-primary">
                    <?php echo esc_html__('🔄 Ejecutar Escaneo Ahora', 'aegis-day0'); ?>
                </button>
            </form>
        </div>
        
        <h2><?php echo esc_html__('Alertas detectadas', 'aegis-day0'); ?></h2>
        <table class="widefat fixed striped">
            <thead>
                <tr>
                    <th><?php echo esc_html__('Plugin', 'aegis-day0'); ?></th>
                    <th><?php echo esc_html__('Tipo', 'aegis-day0'); ?></th>
                    <th><?php echo esc_html__('Severidad', 'aegis-day0'); ?></th>
                    <th><?php echo esc_html__('Fuente', 'aegis-day0'); ?></th>
                    <th><?php echo esc_html__('Riesgo Falso Positivo', 'aegis-day0'); ?></th>
                </tr>
            </thead>
            <tbody>
                <?php
                $alerts = get_option('aegis_day0_alerts', []);
                if (!empty($alerts)) {
                    foreach ($alerts as $alert) {
                        $fp_risk = isset($alert['false_positive_risk']) ? $alert['false_positive_risk'] : 'unknown';
                        $fp_indicator = '';
                        if ($fp_risk === 'high') {
                            $fp_indicator = '⚠️ ' . esc_html__('Alto', 'aegis-day0');
                        } elseif ($fp_risk === 'medium') {
                            $fp_indicator = '◐ ' . esc_html__('Medio', 'aegis-day0');
                        } elseif ($fp_risk === 'low') {
                            $fp_indicator = '✓ ' . esc_html__('Bajo', 'aegis-day0');
                        } else {
                            $fp_indicator = '? ' . esc_html__('Desconocido', 'aegis-day0');
                        }
                        ?>
                        <tr>
                            <td><?php echo esc_html($alert['plugin']); ?></td>
                            <td><?php echo esc_html($alert['type']); ?></td>
                            <td><?php echo esc_html($alert['severity']); ?></td>
                            <td><?php echo esc_html($alert['source']); ?></td>
                            <td><?php echo $fp_indicator; ?></td>
                        </tr>
                        <?php
                    }
                } else {
                    ?>
                    <tr>
                        <td colspan="5"><?php echo esc_html__('✅ No se detectaron vulnerabilidades', 'aegis-day0'); ?></td>
                    </tr>
                    <?php
                }
                ?>
            </tbody>
        </table>
        
        <div class="notice notice-info" style="margin-top: 20px;">
            <p>
                <strong><?php echo esc_html__('ℹ️ Información:', 'aegis-day0'); ?></strong>
                <?php echo esc_html__('Las alertas con "Riesgo de Falso Positivo Alto" deben ser revisadas manualmente antes de tomar acciones.', 'aegis-day0'); ?>
            </p>
        </div>

        <h2><?php echo esc_html__('📤 Exportar Datos', 'aegis-day0'); ?></h2>
        <form method="post">
            <?php wp_nonce_field('aegis_day0_export_action', 'aegis_day0_export_nonce'); ?>
            <button type="submit" name="aegis_day0_export" value="csv" class="button button-primary"><?php echo esc_html__('Exportar CSV', 'aegis-day0'); ?></button>
            <button type="submit" name="aegis_day0_export" value="json" class="button"><?php echo esc_html__('Exportar JSON', 'aegis-day0'); ?></button>
        </form>
    </div>
    <?php
}

/**
 * Configuración - Vista de ajustes del plugin
 */
function aegis_day0_config() {
    // Handle save message
    $save_message = '';
    if (isset($_POST['aegis_day0_save_settings']) && current_user_can('manage_options')) {
        if (isset($_POST['aegis_day0_config_nonce']) && wp_verify_nonce($_POST['aegis_day0_config_nonce'], 'aegis_day0_config_action')) {
            // Settings are saved via register_setting automatically
            $save_message = '<div class="notice notice-success"><p>' . esc_html__('✅ Configuración guardada exitosamente', 'aegis-day0') . '</p></div>';
        } else {
            $save_message = '<div class="notice notice-error"><p>' . esc_html__('❌ Error de seguridad al guardar configuración', 'aegis-day0') . '</p></div>';
        }
    }
    ?>
    <div class="wrap aegis-day0-config">
        <?php echo $save_message; ?>
        <h1><?php echo esc_html__('⚙️ Aegis Day0 - Configuración', 'aegis-day0'); ?></h1>
        
        <form method="post" action="options.php">
            <?php settings_fields('aegis_day0_settings'); ?>
            <?php do_settings_sections('aegis_day0_settings'); ?>
            
            <h2><?php echo esc_html__('Configuración General', 'aegis-day0'); ?></h2>
            <table class="form-table">
                <tr>
                    <th scope="row">
                        <label for="aegis_day0_auto_disable"><?php echo esc_html__('Auto-desactivación', 'aegis-day0'); ?></label>
                    </th>
                    <td>
                        <label>
                            <input type="checkbox" name="aegis_day0_auto_disable" id="aegis_day0_auto_disable" value="1"
                                <?php checked(1, get_option('aegis_day0_auto_disable', 0)); ?> />
                            <?php echo esc_html__('Desactivar automáticamente plugins vulnerables críticos', 'aegis-day0'); ?>
                        </label>
                        <p class="description"><?php echo esc_html__('Esta opción desactivará automáticamente los plugins críticos que presenten vulnerabilidades de alta severidad.', 'aegis-day0'); ?></p>
                    </td>
                </tr>
            </table>
            
            <h2><?php echo esc_html__('Configuración de Reportes', 'aegis-day0'); ?></h2>
            <table class="form-table">
                <tr>
                    <th scope="row">
                        <label for="aegis_day0_report_frequency"><?php echo esc_html__('Frecuencia', 'aegis-day0'); ?></label>
                    </th>
                    <td>
                        <select name="aegis_day0_report_frequency" id="aegis_day0_report_frequency">
                            <option value="daily" <?php selected(get_option('aegis_day0_report_frequency'), 'daily'); ?>><?php echo esc_html__('Diario', 'aegis-day0'); ?></option>
                            <option value="weekly" <?php selected(get_option('aegis_day0_report_frequency'), 'weekly'); ?>><?php echo esc_html__('Semanal', 'aegis-day0'); ?></option>
                            <option value="monthly" <?php selected(get_option('aegis_day0_report_frequency'), 'monthly'); ?>><?php echo esc_html__('Mensual', 'aegis-day0'); ?></option>
                        </select>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="aegis_day0_report_time"><?php echo esc_html__('Hora de envío', 'aegis-day0'); ?></label>
                    </th>
                    <td>
                        <input type="time" name="aegis_day0_report_time" id="aegis_day0_report_time"
                            value="<?php echo esc_attr(get_option('aegis_day0_report_time', '08:00')); ?>" />
                        <p class="description"><?php echo esc_html__('Hora en la que se enviarán los reportes programados.', 'aegis-day0'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="aegis_day0_report_recipients"><?php echo esc_html__('Destinatarios', 'aegis-day0'); ?></label>
                    </th>
                    <td>
                        <input type="email" name="aegis_day0_report_recipients" id="aegis_day0_report_recipients"
                            value="<?php echo esc_attr(get_option('aegis_day0_report_recipients', '')); ?>" 
                            placeholder="<?php echo esc_attr__('admin@example.com, security@example.com', 'aegis-day0'); ?>" 
                            style="width:100%;" />
                        <p class="description"><?php echo esc_html__('Correos electrónicos separados por coma para recibir los reportes.', 'aegis-day0'); ?></p>
                    </td>
                </tr>
            </table>
            
            <h2><?php echo esc_html__('Integración WPScan', 'aegis-day0'); ?></h2>
            <table class="form-table">
                <tr>
                    <th scope="row">
                        <label for="aegis_day0_wpscan_token"><?php echo esc_html__('API Token', 'aegis-day0'); ?></label>
                    </th>
                    <td>
                        <input type="password" name="aegis_day0_wpscan_token" id="aegis_day0_wpscan_token"
                            value="<?php echo esc_attr(get_option('aegis_day0_wpscan_token', '')); ?>" 
                            style="width:100%; max-width: 400px;" />
                        <p class="description">
                            <?php echo esc_html__('Obtén tu token gratuito en', 'aegis-day0'); ?> 
                            <a href="https://wpscan.com/" target="_blank" rel="noopener noreferrer">wpscan.com</a>
                        </p>
                        <p class="description"><?php echo esc_html__('El token se utiliza para consultar la base de datos de vulnerabilidades de WPScan.', 'aegis-day0'); ?></p>
                    </td>
                </tr>
            </table>
            
            <?php wp_nonce_field('aegis_day0_config_action', 'aegis_day0_config_nonce'); ?>
            <?php submit_button(__('Guardar Configuración', 'aegis-day0')); ?>
        </form>
    </div>
    <?php
}