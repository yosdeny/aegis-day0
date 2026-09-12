<?php
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
    exit;
}

// Delete all plugin options
delete_option('aegis_day0_auto_disable');
delete_option('aegis_day0_report_frequency');
delete_option('aegis_day0_report_time');
delete_option('aegis_day0_report_recipients');
delete_option('aegis_day0_wpscan_token');
delete_option('aegis_day0_alerts');
delete_option('aegis_day0_logs');
delete_option('aegis_day0_notified_alerts');
delete_option('aegis_day0_fp_db_version');

// Drop the false positives table
global $wpdb;
$table_name = $wpdb->prefix . 'aegis_day0_false_positives';
$wpdb->query("DROP TABLE IF EXISTS $table_name");

// Clear scheduled events
wp_clear_scheduled_hook('aegis_day0_send_report');

// Limpiar opciones transitorias y datos del plugin (incluyendo logs de FPs)
$wpdb->query( "DELETE FROM $wpdb->options WHERE option_name LIKE '_transient_aegis_%' OR option_name LIKE 'aegis_day0_%'" );

// Limpiar cualquier otra opción residual que pueda haber quedado
$wpdb->query( "DELETE FROM $wpdb->options WHERE option_name LIKE '%aegis%day0%'" );