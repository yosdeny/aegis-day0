# 📝 Ejemplo de Integración del Validador en class-false-positive-manager.php

## Cambio Requerido

### 1. Incluir el archivo del validador en la cabecera del plugin principal

En tu archivo principal del plugin (ej: `aegis-day0.php` o similar), agrega:

```php
// Después de las constantes y antes de cargar las clases
require_once plugin_dir_path(__FILE__) . 'includes/class-query-validator.php';
```

### 2. Reemplazar llamadas a `$wpdb->prepare()` por `GRM_Query_Validator::safe_prepare()`

#### Ejemplo 1 - Línea 121-126 (ANTES):

```php
$exists = $wpdb->get_var($wpdb->prepare(
    "SELECT id FROM $table_name WHERE plugin_file = %s AND file_path = %s AND issue_hash = %s",
    $plugin_file,
    $file_path,
    $issue_hash
));
```

#### Ejemplo 1 - Línea 121-126 (DESPUÉS con validador):

```php
$prepared_query = GRM_Query_Validator::safe_prepare(
    $wpdb,
    "SELECT id FROM $table_name WHERE plugin_file = %s AND file_path = %s AND issue_hash = %s",
    $plugin_file,
    $file_path,
    $issue_hash
);
$exists = $wpdb->get_var($prepared_query);
```

---

## Todos los Cambios Necesarios

| Línea | Código Original | Código con Validador |
|-------|----------------|---------------------|
| 121-126 | `$wpdb->prepare("SELECT id...", $plugin_file, $file_path, $issue_hash)` | `GRM_Query_Validator::safe_prepare($wpdb, "SELECT id...", $plugin_file, $file_path, $issue_hash)` |
| 193-199 | `$wpdb->prepare("SELECT issue_hash...", $plugin_file)` | `GRM_Query_Validator::safe_prepare($wpdb, "SELECT issue_hash...", $plugin_file)` |
| 201-208 | `$wpdb->prepare("SELECT issue_hash... WHERE plugin_file = %s AND file_path = %s", $plugin_file, $file_path)` | `GRM_Query_Validator::safe_prepare($wpdb, "SELECT issue_hash... WHERE plugin_file = %s AND file_path = %s", $plugin_file, $file_path)` |
| 235-240 | `$wpdb->prepare("SELECT id... WHERE plugin_file = %s AND issue_hash = %s", $plugin_file, $issue_hash)` | `GRM_Query_Validator::safe_prepare($wpdb, "SELECT id... WHERE plugin_file = %s AND issue_hash = %s", $plugin_file, $issue_hash)` |
| 242-248 | `$wpdb->prepare("SELECT id... WHERE plugin_file = %s AND file_path = %s AND issue_hash = %s", $plugin_file, $file_path, $issue_hash)` | `GRM_Query_Validator::safe_prepare($wpdb, "SELECT id... WHERE plugin_file = %s AND file_path = %s AND issue_hash = %s", $plugin_file, $file_path, $issue_hash)` |
| 487-490 | `$wpdb->prepare("SELECT plugin_file... WHERE id = %d", $id)` | `GRM_Query_Validator::safe_prepare($wpdb, "SELECT plugin_file... WHERE id = %d", $id)` |
| 546-549 | `$wpdb->prepare("SELECT issue_hash... WHERE plugin_file = %s", $plugin_file)` | `GRM_Query_Validator::safe_prepare($wpdb, "SELECT issue_hash... WHERE plugin_file = %s", $plugin_file)` |
| 594-597 | `$wpdb->prepare("SELECT issue_hash... WHERE plugin_file = %s", $plugin_file)` | `GRM_Query_Validator::safe_prepare($wpdb, "SELECT issue_hash... WHERE plugin_file = %s", $plugin_file)` |

---

## Script de Migración Automática (Opcional)

Puedes usar este comando bash para reemplazar automáticamente todas las ocurrencias:

```bash
#!/bin/bash
# migrate-to-validator.sh

FILE="includes/class-false-positive-manager.php"

echo "⚠️  ADVERTENCIA: Esto es solo una guía. Los reemplazos automáticos pueden romper el código."
echo "Se recomienda hacer los cambios manualmente para revisar cada caso."
echo ""
echo "Para migrar manualmente:"
echo "1. Busca: \$wpdb->prepare("
echo "2. Reemplaza por: GRM_Query_Validator::safe_prepare(\$wpdb,"
echo "3. Asegúrate de que la sintaxis sea correcta en cada caso"
```

---

## Verificación Post-Migración

Después de hacer los cambios:

1. **Activar WP_DEBUG** en `wp-config.php`:
   ```php
   define('WP_DEBUG', true);
   define('WP_DEBUG_LOG', true);
   ```

2. **Opcional: Activar modo estricto** (solo desarrollo):
   ```php
   define('GRM_STRICT_DB_CHECK', true);
   ```

3. **Probar funcionalidades del plugin** que usan base de datos:
   - Marcar un reporte como falso positivo
   - Listar falsos positivos
   - Eliminar un falso positivo

4. **Revisar el log** (`wp-content/debug.log`):
   - No debería haber warnings de `wpdb::prepare`
   - Si hay errores, el validador mostrará el archivo y línea exactos

---

## Beneficios de esta Migración

✅ **Detección temprana**: Los errores se detectan en el momento de escribir la consulta, no cuando WordPress lanza el warning genérico.

✅ **Logs limpios**: En lugar de mensajes crípticos desde `functions.php:6260`, verás exactamente qué función y línea causó el problema.

✅ **Modo estricto opcional**: En desarrollo puedes forzar que los errores detengan la ejecución para corregirlos inmediatamente.

✅ **Cero impacto en producción**: El validador solo se activa si `WP_DEBUG` está definido.
