<?php
/**
 * Plugin Name: Aegis Day0
 * Plugin URI: https://github.com/yosdeny
 * Description: Detección proactiva de vulnerabilidades día 0 en plugins de WordPress.
 * Version: 0.4
 * Author: YGB
 * Author URI: https://github.com/yosdeny
 * Text Domain: aegis-day0
 * Requires at least: 7.0
 * Tested up to: 7.1
 * Requires PHP: 8.0
 * Tested PHP: 8.2
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 */

if ( ! defined( 'ABSPATH' ) ) exit;

// Constants
define('AEGIS_DAY0_VERSION', '0.2');
define('AEGIS_DAY0_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('AEGIS_DAY0_PLUGIN_URL', plugin_dir_url(__FILE__));

// Includes
require_once AEGIS_DAY0_PLUGIN_DIR . 'includes/config.php';
require_once AEGIS_DAY0_PLUGIN_DIR . 'includes/class-token-analyzer.php';
require_once AEGIS_DAY0_PLUGIN_DIR . 'includes/class-ast-analyzer.php';
require_once AEGIS_DAY0_PLUGIN_DIR . 'includes/class-scanner.php';
require_once AEGIS_DAY0_PLUGIN_DIR . 'includes/rules.php';
require_once AEGIS_DAY0_PLUGIN_DIR . 'includes/api-wpscan.php';
require_once AEGIS_DAY0_PLUGIN_DIR . 'includes/notify.php';
require_once AEGIS_DAY0_PLUGIN_DIR . 'includes/logger.php';
require_once AEGIS_DAY0_PLUGIN_DIR . 'includes/reports.php';
require_once AEGIS_DAY0_PLUGIN_DIR . 'includes/class-false-positive-manager.php';
require_once AEGIS_DAY0_PLUGIN_DIR . 'admin/dashboard.php';

// Enqueue admin styles
function aegis_day0_enqueue_admin_styles() {
    wp_enqueue_style(
        'aegis-day0-css',
        AEGIS_DAY0_PLUGIN_URL . 'admin/css/dashboard.css',
        [],
        AEGIS_DAY0_VERSION
    );
}
add_action('admin_enqueue_scripts', 'aegis_day0_enqueue_admin_styles');

// Inicialización - movido a cron para evitar ejecución en cada carga de página
function aegis_day0_init() {
    // Inicializar sistema de notificaciones por lotes
    Aegis_Day0_Notify::init_batch_notifications();
    
    $scanner = new Aegis_Day0_Scanner();
    $scanner->run_checks();
}

// Programar escaneo periódico en lugar de ejecutar en cada carga admin
function aegis_day0_schedule_scan() {
    if (!current_user_can('manage_options')) {
        return;
    }
    
    if (!wp_next_scheduled('aegis_day0_run_scan')) {
        wp_schedule_event(time(), 'hourly', 'aegis_day0_run_scan');
    }
}
add_action('admin_init', 'aegis_day0_schedule_scan');

// Ejecutar escaneo vía cron programado
add_action('aegis_day0_run_scan', 'aegis_day0_init');

// Acción manual para forzar escaneo inmediato (desde dashboard)
function aegis_day0_force_scan() {
    if (!current_user_can('manage_options')) {
        return false;
    }
    
    // Clear the scan transient to allow immediate re-scan
    delete_transient('aegis_day0_last_scan');
    
    aegis_day0_init();
    
    return true;
}

// Settings
function aegis_day0_register_settings() {
    // Registrar sección
    add_settings_section(
        'aegis_day0_main_section',
        'Configuración Principal',
        null,
        'aegis_day0_settings_page'
    );
    
    // Registrar campos
    add_settings_field('aegis_day0_auto_disable', 'Auto Desactivar', 'aegis_day0_auto_deactivate_cb', 'aegis_day0_settings_page', 'aegis_day0_main_section');
    add_settings_field('aegis_day0_report_frequency', 'Frecuencia de Reportes', 'aegis_day0_report_frequency_cb', 'aegis_day0_settings_page', 'aegis_day0_main_section');
    add_settings_field('aegis_day0_report_time', 'Hora de Reporte', 'aegis_day0_report_time_cb', 'aegis_day0_settings_page', 'aegis_day0_main_section');
    add_settings_field('aegis_day0_report_recipients', 'Destinatarios', 'aegis_day0_report_recipients_cb', 'aegis_day0_settings_page', 'aegis_day0_main_section');
    add_settings_field('aegis_day0_wpscan_token', 'WPScan Token', 'aegis_day0_wpscan_token_cb', 'aegis_day0_settings_page', 'aegis_day0_main_section');
    
    // Registrar opciones
    register_setting('aegis_day0_settings_group', 'aegis_day0_auto_disable', [
        'type' => 'integer',
        'sanitize_callback' => 'absint',
        'default' => 0
    ]);
    register_setting('aegis_day0_settings_group', 'aegis_day0_report_frequency', [
        'type' => 'string',
        'sanitize_callback' => 'sanitize_text_field',
        'default' => 'weekly'
    ]);
    register_setting('aegis_day0_settings_group', 'aegis_day0_report_time', [
        'type' => 'string',
        'sanitize_callback' => 'sanitize_text_field',
        'default' => '08:00'
    ]);
    register_setting('aegis_day0_settings_group', 'aegis_day0_report_recipients', [
        'type' => 'string',
        'sanitize_callback' => 'sanitize_text_field',
        'default' => ''
    ]);
    register_setting('aegis_day0_settings_group', 'aegis_day0_wpscan_token', [
        'type' => 'string',
        'sanitize_callback' => 'sanitize_text_field',
        'default' => ''
    ]);
}
add_action('admin_init', 'aegis_day0_register_settings');

// Callback functions for settings fields
function aegis_day0_auto_deactivate_cb() {
    $value = get_option('aegis_day0_auto_disable', 0);
    echo '<label><input type="checkbox" name="aegis_day0_auto_disable" value="1" ' . checked(1, $value, false) . ' /> Auto Desactivar plugins críticos</label>';
    echo '<p class="description">Si se marca, los plugins considerados "críticos" se desactivarán solos si se detecta una vulnerabilidad de severidad Critical.</p>';
}

function aegis_day0_report_frequency_cb() {
    $value = get_option('aegis_day0_report_frequency', 'weekly');
    ?>
    <select name="aegis_day0_report_frequency">
        <option value="daily" <?php selected($value, 'daily'); ?>>Diario</option>
        <option value="weekly" <?php selected($value, 'weekly'); ?>>Semanal</option>
        <option value="monthly" <?php selected($value, 'monthly'); ?>>Mensual</option>
    </select>
    <?php
}

function aegis_day0_report_time_cb() {
    $value = get_option('aegis_day0_report_time', '08:00');
    echo '<input type="time" name="aegis_day0_report_time" value="' . esc_attr($value) . '" />';
}

function aegis_day0_report_recipients_cb() {
    $value = get_option('aegis_day0_report_recipients', '');
    echo '<input type="text" name="aegis_day0_report_recipients" value="' . esc_attr($value) . '" class="regular-text" placeholder="email1@ejemplo.com, email2@ejemplo.com" />';
    echo '<p class="description">Separa múltiples emails con comas.</p>';
}

function aegis_day0_wpscan_token_cb() {
    $value = get_option('aegis_day0_wpscan_token', '');
    echo '<input type="password" name="aegis_day0_wpscan_token" value="' . esc_attr($value) . '" class="regular-text" />';
    echo '<p class="description">Obtén tu token gratuito en <a href="https://wpscan.com/" target="_blank">WPScan.com</a>.</p>';
}

// Cron programado
function aegis_day0_schedule_reports() {
    if (!current_user_can('manage_options')) {
        return;
    }
    
    wp_clear_scheduled_hook('aegis_day0_send_report');

    $frequency = get_option('aegis_day0_report_frequency', 'weekly');
    $time = get_option('aegis_day0_report_time', '08:00');
    list($hour, $minute) = explode(':', $time);
    $timestamp = mktime((int)$hour, (int)$minute, 0);

    if ($frequency === 'daily') {
        wp_schedule_event($timestamp, 'daily', 'aegis_day0_send_report');
    } elseif ($frequency === 'weekly') {
        wp_schedule_event($timestamp, 'weekly', 'aegis_day0_send_report');
    } elseif ($frequency === 'monthly') {
        wp_schedule_event($timestamp, 'monthly', 'aegis_day0_send_report');
    }
}
add_action('update_option_aegis_day0_report_frequency', 'aegis_day0_schedule_reports', 10, 2);
add_action('update_option_aegis_day0_report_time', 'aegis_day0_schedule_reports', 10, 2);

add_action('aegis_day0_send_report', ['Aegis_Day0_Reports', 'send_report']);

// Activation hook
function aegis_day0_activate() {
    if (!current_user_can('activate_plugins')) {
        return;
    }
    
    // Set default options
    add_option('aegis_day0_auto_disable', 0);
    add_option('aegis_day0_report_frequency', 'weekly');
    add_option('aegis_day0_report_time', '08:00');
    add_option('aegis_day0_report_recipients', '');
    add_option('aegis_day0_wpscan_token', '');
    add_option('aegis_day0_alerts', []);
    add_option('aegis_day0_logs', []);
    add_option('aegis_day0_notified_alerts', []);
    
    // Crear tabla de falsos positivos
    if (class_exists('Aegis_False_Positive_Manager')) {
        Aegis_False_Positive_Manager::maybe_create_table();
    }
    
    // Schedule initial report
    aegis_day0_schedule_reports();
}
register_activation_hook(__FILE__, 'aegis_day0_activate');

// Deactivation hook
function aegis_day0_deactivate() {
    if (!current_user_can('activate_plugins')) {
        return;
    }
    
    wp_clear_scheduled_hook('aegis_day0_send_report');
}
register_deactivation_hook(__FILE__, 'aegis_day0_deactivate');