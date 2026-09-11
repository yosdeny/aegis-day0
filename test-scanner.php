<?php
/**
 * Script de prueba para verificar el funcionamiento del escáner AST
 */

// Configurar reporte de errores
error_reporting(E_ALL);
ini_set('display_errors', 1);

echo "===========================================\n";
echo "PRUEBA DEL ESCÁNER AEGIS DAY0 - AST\n";
echo "===========================================\n\n";

// Verificar que los archivos existen
$ast_analyzer_path = __DIR__ . '/includes/class-ast-analyzer.php';
$scanner_path = __DIR__ . '/includes/class-scanner.php';
$autoload_path = __DIR__ . '/lib/autoload.php';

echo "[1] Verificando existencia de archivos...\n";
if (!file_exists($autoload_path)) {
    die("ERROR: No se encontró autoload.php en $autoload_path\n");
}
echo "✓ autoload.php existe\n";

if (!file_exists($ast_analyzer_path)) {
    die("ERROR: No se encontró class-ast-analyzer.php en $ast_analyzer_path\n");
}
echo "✓ class-ast-analyzer.php existe\n";

if (!file_exists($scanner_path)) {
    die("ERROR: No se encontró class-scanner.php en $scanner_path\n");
}
echo "✓ class-scanner.php existe\n\n";

// Cargar autoload manual
echo "[2] Cargando autoload de PhpParser...\n";
require_once $autoload_path;
echo "✓ Autoload cargado\n\n";

// Verificar que PhpParser está disponible
echo "[3] Verificando PhpParser...\n";
if (!class_exists('PhpParser\ParserFactory')) {
    die("ERROR: PhpParser\ParserFactory no está disponible\n");
}
echo "✓ PhpParser\ParserFactory disponible\n\n";

// Cargar las clases del escáner
echo "[4] Cargando clases del escáner...\n";
require_once $ast_analyzer_path;
require_once $scanner_path;
echo "✓ Clases cargadas\n\n";

// Archivo a escanear
$test_file = __DIR__ . '/test-samples/malicious-test.php';

echo "[5] Archivo a escanear: $test_file\n";
if (!file_exists($test_file)) {
    die("ERROR: No se encontró el archivo de prueba\n");
}
echo "✓ Archivo de prueba existe\n\n";

// Crear instancia del analizador AST
echo "[6] Iniciando análisis AST...\n";
echo "-------------------------------------------\n\n";

try {
    $analyzer = new Aegis_AST_Analyzer();
    
    // Escanear el archivo
    $start_time = microtime(true);
    $alerts = $analyzer->scan_file($test_file);
    $end_time = microtime(true);
    
    $execution_time = round(($end_time - $start_time) * 1000, 2);
    
    echo "Tiempo de ejecución: {$execution_time} ms\n\n";
    
    if (empty($alerts)) {
        echo "⚠️  No se encontraron alertas (esto es inesperado para un archivo malicioso)\n";
    } else {
        echo "===========================================\n";
        echo "RESULTADOS DEL ESCANEO AST\n";
        echo "===========================================\n";
        echo "Total de alertas encontradas: " . count($alerts) . "\n\n";
        
        // Agrupar por severidad
        $critical = array_filter($alerts, fn($a) => $a['severity'] === 'CRITICAL');
        $high = array_filter($alerts, fn($a) => $a['severity'] === 'HIGH');
        $medium = array_filter($alerts, fn($a) => $a['severity'] === 'MEDIUM');
        $low = array_filter($alerts, fn($a) => $a['severity'] === 'LOW');
        
        echo "🔴 CRÍTICAS: " . count($critical) . "\n";
        echo "🟠 ALTAS: " . count($high) . "\n";
        echo "🟡 MEDIAS: " . count($medium) . "\n";
        echo "🟢 BAJAS: " . count($low) . "\n\n";
        
        echo "-------------------------------------------\n";
        echo "DETALLE DE ALERTAS:\n";
        echo "-------------------------------------------\n\n";
        
        foreach ($alerts as $index => $alert) {
            $severity_icon = '⚪';
            if ($alert['severity'] === 'CRITICAL') {
                $severity_icon = '🔴';
            } elseif ($alert['severity'] === 'HIGH') {
                $severity_icon = '🟠';
            } elseif ($alert['severity'] === 'MEDIUM') {
                $severity_icon = '🟡';
            } elseif ($alert['severity'] === 'LOW') {
                $severity_icon = '🟢';
            }
            
            $function_name = isset($alert['function']) ? $alert['function'] : 'N/A';
            
            echo "{$severity_icon} [#{$index}] {$alert['type']}\n";
            echo "   Severidad: {$alert['severity']}\n";
            echo "   Línea: {$alert['line']}\n";
            echo "   Función: {$function_name}\n";
            echo "   Descripción: {$alert['description']}\n";
            echo "   Código: " . trim($alert['code_snippet']) . "\n";
            echo "\n";
        }
    }
    
} catch (Exception $e) {
    echo "❌ ERROR durante el análisis:\n";
    echo $e->getMessage() . "\n";
    echo "\nStack trace:\n" . $e->getTraceAsString() . "\n";
}

echo "\n===========================================\n";
echo "PRUEBA COMPLETADA\n";
echo "===========================================\n";
