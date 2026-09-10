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

// Clear scheduled events
wp_clear_scheduled_hook('aegis_day0_send_report');