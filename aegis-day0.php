<?php
/**
 * Plugin Name: Aegis Day0
 * Description: Detección proactiva de vulnerabilidades día 0 en plugins de WordPress.
 * Version: 0.1
 * Author: Yosdeny
 */

if ( ! defined( 'ABSPATH' ) ) exit;

// Includes
require_once plugin_dir_path(__FILE__) . 'includes/class-scanner.php';
require_once plugin_dir_path(__FILE__) . 'includes/rules.php';
require_once plugin_dir_path(__FILE__) . 'includes/api-wpscan.php';
require_once plugin_dir_path(__FILE__) . 'includes/notify.php';
require_once plugin_dir_path(__FILE__) . 'includes/logger.php';
require_once plugin_dir_path(__FILE__) . 'includes/reports.php';
require_once plugin_dir_path(__FILE__) . 'admin/dashboard.php';

// Inicialización
function aegis_day0_init() {
    $scanner = new Aegis_Day0_Scanner();
    $scanner->run_checks();
}
add_action('admin_init', 'aegis_day0_init');

// Settings
function aegis_day0_register_settings() {
    register_setting('aegis_day0_settings', 'aegis_day0_auto_disable');
    register_setting('aegis_day0_settings', 'aegis_day0_report_frequency');
    register_setting('aegis_day0_settings', 'aegis_day0_report_time');
    register_setting('aegis_day0_settings', 'aegis_day0_report_recipients');
}
add_action('admin_init', 'aegis_day0_register_settings');

// Cron programado
function aegis_day0_schedule_reports() {
    wp_clear_scheduled_hook('aegis_day0_send_report');

    $frequency = get_option('aegis_day0_report_frequency', 'weekly');
    $time = get_option('aegis_day0_report_time', '08:00');
    list($hour, $minute) = explode(':', $time);
    $timestamp = mktime($hour, $minute, 0);

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