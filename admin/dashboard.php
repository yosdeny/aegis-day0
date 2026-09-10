<?php
function aegis_day0_admin_menu() {
    if ( current_user_can('manage_options') ) {
        add_menu_page(
            'Aegis Day0',
            'Aegis Day0',
            'manage_options',
            'aegis-day0',
            'aegis_day0_dashboard',
            'dashicons-shield-alt',
            80
        );
    }
}
add_action('admin_menu', 'aegis_day0_admin_menu');

function aegis_day0_dashboard() {
    ?>
    <div class="wrap aegis-day0-dashboard">
        <h1>🛡️ Aegis Day0 - Vulnerabilidades</h1>
        
        <h2>Alertas detectadas</h2>
        <table class="widefat fixed striped">
            <thead>
                <tr>
                    <th>Plugin</th>
                    <th>Tipo</th>
                    <th>Severidad</th>
                    <th>Fuente</th>
                </tr>
            </thead>
            <tbody>
                <?php
                $alerts = get_option('aegis_day0_alerts', []);
                if (!empty($alerts)) {
                    foreach ($alerts as $alert) {
                        echo "<tr>
                            <td>{$alert['plugin']}</td>
                            <td>{$alert['type']}</td>
                            <td>{$alert['severity']}</td>
                            <td>{$alert['source']}</td>
                        </tr>";
                    }
                } else {
                    echo "<tr><td colspan='4'>✅ No se detectaron vulnerabilidades</td></tr>";
                }
                ?>
            </tbody>
        </table>

        <h2>📜 Historial de acciones</h2>
        <table class="widefat fixed striped">
            <thead>
                <tr>
                    <th>Fecha</th>
                    <th>Plugin</th>
                    <th>Tipo</th>
                    <th>Severidad</th>
                    <th>Fuente</th>
                    <th>Acción</th>
                </tr>
            </thead>
            <tbody>
                <?php
                $logs = Aegis_Day0_Logger::get_logs();
                if (!empty($logs)) {
                    foreach ($logs as $log) {
                        echo "<tr>
                            <td>{$log['date']}</td>
                            <td>{$log['plugin']}</td>
                            <td>{$log['type']}</td>
                            <td>{$log['severity']}</td>
                            <td>{$log['source']}</td>
                            <td>{$log['action']}</td>
                        </tr>";
                    }
                } else {
                    echo "<tr><td colspan='6'>No hay registros aún</td></tr>";
                }
                ?>
            </tbody>
        </table>

        <h2>⚙️ Configuración</h2>
        <form method="post" action="options.php">
            <?php settings_fields('aegis_day0_settings'); ?>
            <?php do_settings_sections('aegis_day0_settings'); ?>
            <label>
                <input type="checkbox" name="aegis_day0_auto_disable" value="1"
                    <?php checked(1, get_option('aegis_day0_auto_disable', 0)); ?> />
                Desactivar automáticamente plugins vulnerables críticos
            </label><br><br>

            <label for="aegis_day0_report_frequency">Frecuencia de reportes:</label>
            <select name="aegis_day0_report_frequency" id="aegis_day0_report_frequency">
                <option value="daily" <?php selected(get_option('aegis_day0_report_frequency'), 'daily'); ?>>Diario</option>
                <option value="weekly" <?php selected(get_option('aegis_day0_report_frequency'), 'weekly'); ?>>Semanal</option>
                <option value="monthly" <?php selected(get_option('aegis_day0_report_frequency'), 'monthly'); ?>>Mensual</option>
            </select><br><br>

            <label for="aegis_day0_report_time">Hora de envío:</label>
            <input type="time" name="aegis_day0_report_time" id="aegis_day0_report_time"
                value="<?php echo esc_attr(get_option('aegis_day0_report_time', '08:00')); ?>" /><br><br>

            <label for="aegis_day0_report_recipients">Destinatarios del reporte (coma):</label>
            <input type="text" name="aegis_day0_report_recipients" id="aegis_day0_report_recipients"
                value="<?php echo esc_attr(get_option('aegis_day0_report_recipients', '')); ?>" style="width:100%;" />

            <?php submit_button(); ?>
        </form>

        <h2>📤 Exportar Logs</h2>
        <form method="post">
            <button name="aegis_day0_export" value="csv" class="button button-primary">Exportar CSV</button>
            <button name="aegis_day0_export" value="json" class="button">Exportar JSON</button>
        </form>
    </div>
    <?php
}