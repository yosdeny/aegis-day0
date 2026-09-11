<?php
/**
 * Script de prueba para el analizador AST
 */

require_once __DIR__ . '/includes/class-ast-analyzer.php';
require_once __DIR__ . '/lib/autoload.php';

echo "=== PROBANDO ANALIZADOR AST ===\n\n";

$test_file = __DIR__ . '/test-vuln/test-ajax.php';

if (!file_exists($test_file)) {
    echo "ERROR: El archivo de prueba no existe: $test_file\n";
    exit(1);
}

echo "Archivo a analizar: $test_file\n\n";

$analyzer = new Aegis_AST_Analyzer();
$alerts = $analyzer->analyze_file($test_file);

echo "=== RESULTADOS DEL ANALISIS AST ===\n\n";
echo "Total alertas encontradas: " . count($alerts) . "\n\n";

if (empty($alerts)) {
    echo "⚠️  NO SE DETECTARON ALERTAS - Esto es incorrecto!\n";
    echo "El archivo test-ajax.php contiene vulnerabilidades intencionales.\n";
} else {
    foreach ($alerts as $i => $alert) {
        $num = $i + 1;
        echo "━━━ ALERTA #$num ━━━\n";
        echo "  Tipo:       " . $alert['type'] . "\n";
        echo "  Funcion:    " . $alert['function'] . "\n";
        echo "  Severidad:  " . $alert['severity'] . "\n";
        echo "  Linea:      " . $alert['line'] . "\n";
        echo "  Descripcion:" . $alert['description'] . "\n";
        echo "  Recomen:    " . substr($alert['recommendation'], 0, 80) . "...\n";
        echo "\n";
    }
}

// Verificaciones especificas
echo "\n=== VERIFICACIONES ESPECIFICAS ===\n";

$has_ajax_nopriv = false;
$has_wpdb_get_var = false;
$has_sql_concat = false;

foreach ($alerts as $alert) {
    if (strpos($alert['function'], 'wp_ajax_nopriv') !== false || 
        (isset($alert['type']) && $alert['type'] === 'ajax_security')) {
        $has_ajax_nopriv = true;
    }
    if (strpos($alert['function'], '$wpdb->get_var') !== false) {
        $has_wpdb_get_var = true;
    }
    if ($alert['uses_user_input'] ?? false) {
        $has_sql_concat = true;
    }
}

echo "✓ AJAX nopriv detectado: " . ($has_ajax_nopriv ? 'SI' : 'NO') . "\n";
echo "✓ WPDB get_var detectado: " . ($has_wpdb_get_var ? 'SI' : 'NO') . "\n";
echo "✓ Concatenacion SQL detectada: " . ($has_sql_concat ? 'SI' : 'NO') . "\n";

echo "\n=== FIN DE LA PRUEBA ===\n";
