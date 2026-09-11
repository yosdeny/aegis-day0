<?php
spl_autoload_register(function ($class) {
    $prefix = 'PhpParser\\';
    $baseDir = __DIR__ . '/PhpParser/';

    if (strncmp($prefix, $class, strlen($prefix)) !== 0) {
        return;
    }

    $relative = substr($class, strlen($prefix));
    $file = $baseDir . str_replace('\\', '/', $relative) . '.php';

    if (file_exists($file)) {
        require $file;
    }
});