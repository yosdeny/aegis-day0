<?php
function aegis_day0_admin_menu() {
    if ( ! current_user_can('manage_options') ) {
        return;
    }
    
    add_menu_page(
        __('Aegis Day0', 'aegis-day0'),
        __('Aegis Day0', 'aegis-day0'),
        'manage_options',
        'aegis-day0',
        'aegis_day0_dashboard',
        'dashicons-shield-alt',
        80
    );
}
add_action('admin_menu', 'aegis_day0_admin_menu');

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
    ?>
    <div class="wrap aegis-day0-dashboard">
        <h1><?php echo esc_html__('🛡️ Aegis Day0 - Vulnerabilidades', 'aegis-day0'); ?></h1>
        
        <h2><?php echo esc_html__('Alertas detectadas', 'aegis-day0'); ?></h2>
        <table class="widefat fixed striped">
            <thead>
                <tr>
                    <th><?php echo esc_html__('Plugin', 'aegis-day0'); ?></th>
                    <th><?php echo esc_html__('Tipo', 'aegis-day0'); ?></th>
                    <th><?php echo esc_html__('Severidad', 'aegis-day0'); ?></th>
                    <th><?php echo esc_html__('Fuente', 'aegis-day0'); ?></th>
                </tr>
            </thead>
            <tbody>
                <?php
                $alerts = get_option('aegis_day0_alerts', []);
                if (!empty($alerts)) {
                    foreach ($alerts as $alert) {
                        ?>
                        <tr>
                            <td><?php echo esc_html($alert['plugin']); ?></td>
                            <td><?php echo esc_html($alert['type']); ?></td>
                            <td><?php echo esc_html($alert['severity']); ?></td>
                            <td><?php echo esc_html($alert['source']); ?></td>
                        </tr>
                        <?php
                    }
                } else {
                    ?>
                    <tr>
                        <td colspan="4"><?php echo esc_html__('✅ No se detectaron vulnerabilidades', 'aegis-day0'); ?></td>
                    </tr>
                    <?php
                }
                ?>
            </tbody>
        </table>

        <h2><?php echo esc_html__('📜 Historial de acciones', 'aegis-day0'); ?></h2>
        <table class="widefat fixed striped">
            <thead>
                <tr>
                    <th><?php echo esc_html__('Fecha', 'aegis-day0'); ?></th>
                    <th><?php echo esc_html__('Plugin', 'aegis-day0'); ?></th>
                    <th><?php echo esc_html__('Tipo', 'aegis-day0'); ?></th>
                    <th><?php echo esc_html__('Severidad', 'aegis-day0'); ?></th>
                    <th><?php echo esc_html__('Fuente', 'aegis-day0'); ?></th>
                    <th><?php echo esc_html__('Acción', 'aegis-day0'); ?></th>
                </tr>
            </thead>
            <tbody>
                <?php
                $logs = Aegis_Day0_Logger::get_logs();
                if (!empty($logs)) {
                    foreach ($logs as $log) {
                        ?>
                        <tr>
                            <td><?php echo esc_html($log['date']); ?></td>
                            <td><?php echo esc_html($log['plugin']); ?></td>
                            <td><?php echo esc_html($log['type']); ?></td>
                            <td><?php echo esc_html($log['severity']); ?></td>
                            <td><?php echo esc_html($log['source']); ?></td>
                            <td><?php echo esc_html($log['action']); ?></td>
                        </tr>
                        <?php
                    }
                } else {
                    ?>
                    <tr>
                        <td colspan="6"><?php echo esc_html__('No hay registros aún', 'aegis-day0'); ?></td>
                    </tr>
                    <?php
                }
                ?>
            </tbody>
        </table>

        <h2><?php echo esc_html__('⚙️ Configuración', 'aegis-day0'); ?></h2>
        <form method="post" action="options.php">
            <?php settings_fields('aegis_day0_settings'); ?>
            <?php do_settings_sections('aegis_day0_settings'); ?>
            <label>
                <input type="checkbox" name="aegis_day0_auto_disable" value="1"
                    <?php checked(1, get_option('aegis_day0_auto_disable', 0)); ?> />
                <?php echo esc_html__('Desactivar automáticamente plugins vulnerables críticos', 'aegis-day0'); ?>
            </label><br><br>

            <label for="aegis_day0_report_frequency"><?php echo esc_html__('Frecuencia de reportes:', 'aegis-day0'); ?></label>
            <select name="aegis_day0_report_frequency" id="aegis_day0_report_frequency">
                <option value="daily" <?php selected(get_option('aegis_day0_report_frequency'), 'daily'); ?>><?php echo esc_html__('Diario', 'aegis-day0'); ?></option>
                <option value="weekly" <?php selected(get_option('aegis_day0_report_frequency'), 'weekly'); ?>><?php echo esc_html__('Semanal', 'aegis-day0'); ?></option>
                <option value="monthly" <?php selected(get_option('aegis_day0_report_frequency'), 'monthly'); ?>><?php echo esc_html__('Mensual', 'aegis-day0'); ?></option>
            </select><br><br>

            <label for="aegis_day0_report_time"><?php echo esc_html__('Hora de envío:', 'aegis-day0'); ?></label>
            <input type="time" name="aegis_day0_report_time" id="aegis_day0_report_time"
                value="<?php echo esc_attr(get_option('aegis_day0_report_time', '08:00')); ?>" /><br><br>

            <label for="aegis_day0_report_recipients"><?php echo esc_html__('Destinatarios del reporte (coma):', 'aegis-day0'); ?></label>
            <input type="text" name="aegis_day0_report_recipients" id="aegis_day0_report_recipients"
                value="<?php echo esc_attr(get_option('aegis_day0_report_recipients', '')); ?>" style="width:100%;" /><br><br>

            <label for="aegis_day0_wpscan_token"><?php echo esc_html__('WPScan API Token:', 'aegis-day0'); ?></label>
            <input type="password" name="aegis_day0_wpscan_token" id="aegis_day0_wpscan_token"
                value="<?php echo esc_attr(get_option('aegis_day0_wpscan_token', '')); ?>" style="width:100%;" />
            <p class="description"><?php echo esc_html__('Obtén tu token gratuito en wpscan.com', 'aegis-day0'); ?></p>

            <?php submit_button(); ?>
        </form>

        <h2><?php echo esc_html__('📤 Exportar Logs', 'aegis-day0'); ?></h2>
        <form method="post">
            <?php wp_nonce_field('aegis_day0_export_action', 'aegis_day0_export_nonce'); ?>
            <button type="submit" name="aegis_day0_export" value="csv" class="button button-primary"><?php echo esc_html__('Exportar CSV', 'aegis-day0'); ?></button>
            <button type="submit" name="aegis_day0_export" value="json" class="button"><?php echo esc_html__('Exportar JSON', 'aegis-day0'); ?></button>
        </form>
    </div>
    <?php
}