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
            $scanner->run_all_checks();
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
            $scanner->run_all_checks();
            
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
    
    // Agrupar alertas por plugin para aplicar el filtro correctamente
    $alerts_by_plugin = [];
    foreach ($alerts as $alert) {
        $plugin_file = isset($alert['plugin']) ? $alert['plugin'] : (isset($alert['plugin_file']) ? $alert['plugin_file'] : 'unknown');
        if (!isset($alerts_by_plugin[$plugin_file])) {
            $alerts_by_plugin[$plugin_file] = [];
        }
        $alerts_by_plugin[$plugin_file][] = $alert;
    }
    
    // Aplicar filtro de falsos positivos por cada plugin
    if (class_exists('Aegis_Day0_False_Positive_Manager')) {
        $filtered_alerts = [];
        foreach ($alerts_by_plugin as $plugin_file => $plugin_alerts) {
            $filtered = apply_filters('aegis_day0_filter_alerts', $plugin_alerts, $plugin_file);
            $filtered_alerts = array_merge($filtered_alerts, $filtered);
        }
        $alerts = $filtered_alerts;
    }
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
                            <th style="width: 30%;">Tipo</th>
                            <th style="width: 10%;">Severidad</th>
                            <th style="width: 15%;">Fuente</th>
                            <th style="width: 15%;">Riesgo Falso Positivo</th>
                            <th style="width: 10%;">Acciones</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($alerts as $alert) : 
                            $fp_risk = isset($alert['false_positive_risk']) ? $alert['false_positive_risk'] : 'Desconocido';
                            $icon = ($fp_risk === 'Alto') ? '⚠️' : (($fp_risk === 'Medio') ? '◐' : '✅');
                            $severity_color = ($alert['severity'] === 'Critical') ? 'red' : 'orange';
                            $is_fp = isset($alert['is_false_positive']) && $alert['is_false_positive'];
                            
                            // Soporte para diferentes nombres de claves para el archivo
                            $file_path = isset($alert['file']) ? $alert['file'] : (isset($alert['file_path']) ? $alert['file_path'] : '');
                            $plugin_file = isset($alert['plugin']) ? $alert['plugin'] : (isset($alert['plugin_file']) ? $alert['plugin_file'] : '');
                            $plugin_name = isset($alert['plugin_name']) ? $alert['plugin_name'] : $plugin_file;
                        ?>
                        <tr<?php echo $is_fp ? ' style="background-color: #f0f0f1; opacity: 0.7;"' : ''; ?>>
                            <td><strong><?php echo esc_html($plugin_name); ?></strong></td>
                            <td><?php echo esc_html($alert['type']); ?></td>
                            <td><span style="color: <?php echo $severity_color; ?>; font-weight: bold;"><?php echo esc_html($alert['severity']); ?></span></td>
                            <td><?php echo esc_html($alert['source']); ?></td>
                            <td><?php echo $icon . ' ' . esc_html($fp_risk); ?></td>
                            <td>
                                <?php if (!$is_fp && !empty($plugin_file)) : ?>
                                    <button class="button button-small mark-fp" 
                                            data-plugin="<?php echo esc_attr($plugin_file); ?>"
                                            data-type="<?php echo esc_attr($alert['type']); ?>"
                                            data-function="<?php echo esc_attr(isset($alert['function']) ? $alert['function'] : ''); ?>"
                                            data-line="<?php echo esc_attr(isset($alert['line']) ? $alert['line'] : 0); ?>"
                                            data-severity="<?php echo esc_attr($alert['severity']); ?>"
                                            data-source="<?php echo esc_attr($alert['source']); ?>">
                                        🚫 Marcar como FP
                                    </button>
                                <?php elseif ($is_fp) : ?>
                                    <span style="color: #666; font-style: italic;">Marcado como FP</span>
                                <?php else : ?>
                                    <span style="color: #999; font-size: 11px;">Sin datos de plugin</span>
                                <?php endif; ?>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php endif; ?>
    </div>
    
    <!-- Modal para marcar como falso positivo -->
    <div id="aegis-fp-modal" style="display:none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 999999;">
        <div style="position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); background: #fff; padding: 30px; border-radius: 5px; max-width: 500px; width: 90%;">
            <h3 style="margin-top: 0;">🚫 Marcar como Falso Positivo</h3>
            <p id="aegis-fp-info" style="color: #666; margin-bottom: 20px;"></p>
            <textarea id="aegis-fp-notes" placeholder="Notas opcionales: ¿Por qué es un falso positivo?" style="width: 100%; height: 100px; margin-bottom: 15px;"></textarea>
            <div style="text-align: right;">
                <button id="aegis-fp-cancel" class="button">Cancelar</button>
                <button id="aegis-fp-confirm" class="button button-primary">Confirmar</button>
            </div>
        </div>
    </div>
    
    <script>
    jQuery(document).ready(function($) {
        var currentAlert = null;
        
        // Click en botón "Marcar como FP"
        $(document).on('click', '.mark-fp', function(e) {
            e.preventDefault();
            
            var $btn = $(this);
            var pluginFile = $btn.attr('data-plugin');
            // Ya no se usa data-file porque puede haber múltiples archivos
            var issueType = $btn.attr('data-type') || 'generic';
            var issueFunction = $btn.attr('data-function') || '';
            var issueLine = $btn.attr('data-line') || 0;
            var issueSeverity = $btn.attr('data-severity') || 'Unknown';
            var issueSource = $btn.attr('data-source') || '';
            
            console.log('=== DATOS DEL BOTÓN ===');
            console.log('plugin:', pluginFile);
            console.log('type:', issueType);
            console.log('Todos los data attributes:', $btn.data());
            
            currentAlert = {
                plugin_file: pluginFile,
                file_path: null, // Se establecerá null porque ya no viene del botón
                issue_type: issueType,
                issue_function: issueFunction,
                issue_line: issueLine,
                issue_severity: issueSeverity,
                issue_source: issueSource
            };
            
            // Validar datos mínimos requeridos - solo necesitamos el plugin_file
            if (!currentAlert.plugin_file) {
                alert('❌ Error: No se pudo identificar el plugin.\n\nPlugin: "' + (currentAlert.plugin_file || 'VACÍO') + '"\n\nRevisa la consola (F12) para ver todos los datos disponibles.');
                console.error('❌ Datos incompletos para marcar como FP:', currentAlert);
                return;
            }
            
            // Si no hay file_path, es porque puede haber múltiples archivos o aún no se ha determinado
            // Esto es normal y permitimos continuar solo con el plugin_file
            if (!currentAlert.file_path) {
                console.log('⚠️ Nota: No hay file_path específico, se marcará todo el plugin como FP');
            }
            
            $('#aegis-fp-info').text(
                'Plugin: ' + currentAlert.plugin_file + '\n' +
                (currentAlert.file_path ? 'Archivo: ' + currentAlert.file_path + '\n' : '') +
                'Tipo: ' + currentAlert.issue_type + '\n' +
                'Línea: ' + currentAlert.issue_line
            );
            $('#aegis-fp-modal').fadeIn();
        });
        
        // Cancelar
        $('#aegis-fp-cancel').click(function() {
            $('#aegis-fp-modal').fadeOut();
            $('#aegis-fp-notes').val('');
            currentAlert = null;
        });
        
        // Confirmar
        $('#aegis-fp-confirm').click(function() {
            if (!currentAlert) return;
            
            var notes = $('#aegis-fp-notes').val();
            
            // Asegurar que issue_type tenga un valor por defecto si está vacío
            if (!currentAlert.issue_type || currentAlert.issue_type === '') {
                currentAlert.issue_type = 'generic';
            }
            
            console.log('=== ENVIANDO AJAX ===');
            console.log('Datos:', currentAlert);
            console.log('Notas:', notes);
            
            $.ajax({
                url: ajaxurl,
                type: 'POST',
                data: {
                    action: 'aegis_mark_false_positive',
                    nonce: '<?php echo wp_create_nonce('aegis_day0_nonce'); ?>',
                    plugin_file: currentAlert.plugin_file,
                    file_path: currentAlert.file_path,
                    issue_type: currentAlert.issue_type,
                    issue_function: currentAlert.issue_function,
                    issue_line: currentAlert.issue_line,
                    issue_severity: currentAlert.issue_severity,
                    issue_source: currentAlert.issue_source,
                    notes: notes
                },
                success: function(response) {
                    console.log('=== RESPUESTA DEL SERVIDOR ===');
                    console.log('Response:', response);
                    
                    if (response.success) {
                        alert('✅ ' + response.data.message);
                        location.reload();
                    } else {
                        var errorMsg = response.data?.message || 'Error desconocido';
                        console.error('❌ Error del servidor:', errorMsg);
                        alert('❌ Error: ' + errorMsg);
                    }
                },
                error: function(xhr, status, error) {
                    console.error('=== ERROR AJAX ===');
                    console.error('Status:', status);
                    console.error('Error:', error);
                    console.error('XHR Response:', xhr.responseText);
                    alert('❌ Error de conexión: ' + status + '\n\nRevisa la consola para más detalles.');
                }
            });
            
            $('#aegis-fp-modal').fadeOut();
            $('#aegis-fp-notes').val('');
            currentAlert = null;
        });
        
        // Cerrar modal al hacer click fuera
        $('#aegis-fp-modal').click(function(e) {
            if ($(e.target).is('#aegis-fp-modal')) {
                $('#aegis-fp-modal').fadeOut();
                $('#aegis-fp-notes').val('');
                currentAlert = null;
            }
        });
    });
    </script>
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
