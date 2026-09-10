<?php
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) exit;

delete_option('aegis_day0_auto_disable');
delete_option('aegis_day0_report_frequency');
delete_option('aegis_day0_report_time');
delete_option('aegis_day0_report_recipients');
delete_option('aegis_day0_alerts');
delete_option('aegis_day0_logs');