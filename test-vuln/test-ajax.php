<?php
/**
 * Plugin de prueba para vulnerabilidades AJAX
 */

// Registra endpoints AJAX para usuarios no autenticados y autenticados
add_action('wp_ajax_nopriv_test_vuln_action', 'test_vuln_callback');
add_action('wp_ajax_test_vuln_action', 'test_vuln_callback');

function test_vuln_callback() {
    // Callback de prueba
    echo "Test";
    wp_die();
}
