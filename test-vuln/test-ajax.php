<?php
/**
 * Plugin de prueba para vulnerabilidades AJAX y SQL Injection
 */

// Registra endpoints AJAX para usuarios no autenticados y autenticados
add_action('wp_ajax_nopriv_test_vuln_action', 'test_vuln_callback');
add_action('wp_ajax_test_vuln_action', 'test_vuln_callback');

function test_vuln_callback() {
    global $wpdb;

    // VULNERABILIDAD 1: Falta de verificación de Nonce (CSRF / Acceso directo)
    // No se utiliza wp_verify_nonce().

    // VULNERABILIDAD 2: Inyección SQL
    // El parámetro $_GET se extrae sin sanitizar ni validar.
    $user_id = isset($_GET['user_id']) ? $_GET['user_id'] : 0;

    // VULNERABILIDAD 3: Concatenación directa en la consulta
    // No se utiliza $wpdb->prepare() para escapar los parámetros.
    $query = "SELECT user_login FROM {$wpdb->users} WHERE ID = " . $user_id;
    
    $result = $wpdb->get_var($query);

    wp_send_json_success(['user' => $result]);
    wp_die();
}
