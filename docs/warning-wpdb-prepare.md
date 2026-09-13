# ⚠️ AVISO: Prevención de Warnings en $wpdb->prepare()

## Descripción del Problema

WordPress genera el siguiente warning cuando hay una mala correspondencia entre los marcadores de posición y los argumentos en consultas preparadas:

```
PHP Notice: La función wpdb::prepare ha sido llamada de forma incorrecta. 
La consulta no contiene el número correcto de marcadores (X) para el número 
de argumentos pasados (Y).
```

**Esto NO es un error crítico**, pero es una **mala práctica** que ensucia los logs de depuración y debe ser evitada.

---

## 🛠️ Solución Implementada en el Plugin

Se ha creado la clase `GRM_Query_Validator` (`includes/class-query-validator.php`) que proporciona validación automática de consultas preparadas.

### 1. Método Helper `safe_prepare()`

**Propósito:** Reemplazar las llamadas directas a `$wpdb->prepare()` con una versión validada que detecta errores antes que WordPress.

**Uso:**

```php
// ❌ ANTES (Sin validación - puede generar warnings silenciosos)
$wpdb->prepare("SELECT * FROM table WHERE id = %d AND status = %s", $id);

// ✅ AHORA (Con validación integrada - detecta el error inmediatamente)
GRM_Query_Validator::safe_prepare($wpdb, "SELECT * FROM table WHERE id = %d AND status = %s", $id, $status);
```

**Ventajas:**
- ✅ Detecta inmediatamente si el número de marcadores no coincide con los argumentos
- ✅ Registra en el log **archivo exacto, línea y función** que hizo la llamada incorrecta
- ✅ Opcionalmente puede detener la ejecución en desarrollo con `GRM_STRICT_DB_CHECK`
- ✅ Muestra backtrace completo para identificar rápidamente el origen del problema

### 2. Características del Validador

| Característica | Descripción |
|---------------|-------------|
| **Solo en Debug** | Solo se activa si `WP_DEBUG` está definido como `true` (cero impacto en producción) |
| **Backtrace Detallado** | Muestra quién llamó, desde qué archivo y línea exacta |
| **Modo Estricto** | Con `define('GRM_STRICT_DB_CHECK', true)` convierte warnings en errores fatales visibles |
| **Prevención de Bucles** | Usa bandera interna `$is_validating` para evitar recursión infinita |
| **Ignora Marcadores Escapados** | Correctamente ignora `%%` en las consultas (por ejemplo, `LIKE '%%search%%'`) |

### 3. Ejemplo de Log Generado

Cuando se detecta un error, el log mostrará información precisa:

```
[GRM VALIDATOR] ERROR DE PREPARACIÓN DE CONSULTA DETECTADO:
- Archivo/Origen: wp-content/plugins/gloria-ri-mercado/includes/class-false-positive-manager.php en la línea 125 (Función: get_records)
- Consulta: SELECT * FROM wp_table WHERE id = %d AND status = %s
- Marcadores encontrados: 2
- Argumentos pasados: 1
- Argumentos recibidos: [42]
--------------------------------------------------
```

**Comparación con el warning original de WordPress:**

| Aspecto | Warning de WordPress | GRM Query Validator |
|---------|---------------------|---------------------|
| Muestra archivo | ❌ No (solo functions.php) | ✅ Sí (archivo real del plugin) |
| Muestra línea | ❌ No | ✅ Sí |
| Muestra función | ❌ No | ✅ Sí |
| Muestra consulta | ❌ No | ✅ Sí |
| Muestra argumentos | ❌ No | ✅ Sí |
| Detiene ejecución | ❌ No | ✅ Opcional (modo estricto) |

### 4. Cómo Integrar en el Código Existente

**Paso 1:** Asegurar que el archivo se carga en el plugin principal:

```php
// En el archivo principal del plugin (ej: gloria-ri-mercado.php)
require_once plugin_dir_path(__FILE__) . 'includes/class-query-validator.php';
```

**Paso 2:** Reemplazar gradualmente las llamadas a `$wpdb->prepare()`:

Búsqueda global en el proyecto:
```bash
grep -rn "\$wpdb->prepare(" /path/to/plugin/
```

Reemplazo manual (recomendado para revisión):
```php
// ANTES
$result = $wpdb->prepare("SELECT * FROM table WHERE id = %d", $id);

// DESPUÉS
$result = GRM_Query_Validator::safe_prepare($wpdb, "SELECT * FROM table WHERE id = %d", $id);
```

**Paso 3 (Opcional):** Activar modo estricto solo en entorno de desarrollo local:

```php
// En wp-config.php (SOLO en desarrollo, NO en producción)
if (defined('WP_ENV') && WP_ENV === 'development') {
    define('GRM_STRICT_DB_CHECK', true);      // Convierte errores en fatales
    define('GRM_RUN_VALIDATOR_TEST', true);   // Ejecuta auto-prueba al iniciar
}
```

---

## 🔍 Auditoría Realizada en el Proyecto Actual

### Archivos con $wpdb->prepare()

Actualmente se encontraron las siguientes llamadas en:

#### `/includes/class-false-positive-manager.php`

| Línea | Consulta | Marcadores | Argumentos | Estado |
|-------|----------|------------|------------|--------|
| 121-126 | `SELECT id FROM... WHERE plugin_file = %s AND file_path = %s AND issue_hash = %s` | 3 (%s, %s, %s) | 3 | ✅ OK |
| 193-199 | `SELECT issue_hash, issue_type, file_path... WHERE plugin_file = %s` | 1 (%s) | 1 | ✅ OK |
| 201-208 | `SELECT issue_hash, issue_type... WHERE plugin_file = %s AND file_path = %s` | 2 (%s, %s) | 2 | ✅ OK |
| 235-240 | `SELECT id FROM... WHERE plugin_file = %s AND issue_hash = %s` | 2 (%s, %s) | 2 | ✅ OK |
| 242-248 | `SELECT id FROM... WHERE plugin_file = %s AND file_path = %s AND issue_hash = %s` | 3 (%s, %s, %s) | 3 | ✅ OK |
| 487-490 | `SELECT plugin_file FROM... WHERE id = %d` | 1 (%d) | 1 | ✅ OK |
| 546-549 | `SELECT issue_hash FROM... WHERE plugin_file = %s` | 1 (%s) | 1 | ✅ OK |
| 594-597 | `SELECT issue_hash FROM... WHERE plugin_file = %s` | 1 (%s) | 1 | ✅ OK |

**Estado actual**: ✅ Todas las llamadas son correctas

**Nota**: El warning que ves en tus logs probablemente proviene de otro plugin o tema en tu instalación de WordPress, no de este código.

---

## Causa del Warning

El warning ocurre cuando:

1. **Más argumentos que marcadores**: Pasas más parámetros de los que la consulta necesita
   ```php
   // ❌ INCORRECTO - 2 argumentos pero solo 1 marcador
   $wpdb->prepare("SELECT * FROM table WHERE id = %d", $id, $extra);
   ```

2. **Menos argumentos que marcadores**: La consulta tiene más marcadores de los necesarios
   ```php
   // ❌ INCORRECTO - 2 marcadores pero solo 1 argumento
   $wpdb->prepare("SELECT * FROM table WHERE id = %d AND status = %s", $id);
   ```

3. **Marcadores mal usados**: Usar `%s` cuando deberías usar `%d`, o viceversa
   ```php
   // ❌ INCORRECTO - Usando %s para un entero
   $wpdb->prepare("SELECT * FROM table WHERE id = %s", $id);
   ```

---

## Cómo Evitarlo

### ✅ Buenas Prácticas

1. **Contar marcadores y argumentos**
   ```php
   // ✅ CORRECTO - 3 marcadores, 3 argumentos
   $wpdb->prepare(
       "SELECT * FROM table WHERE plugin_file = %s AND file_path = %s AND issue_hash = %s",
       $plugin_file,
       $file_path,
       $issue_hash
   );
   ```

2. **Usar el tipo correcto de marcador**
   - `%s` → strings (cadenas de texto)
   - `%d` → integers (enteros)
   - `%f` → floats (números decimales)

3. **Verificar antes de commit**
   - Revisar que cada `%` tenga su argumento correspondiente
   - Contar argumentos en el mismo orden que aparecen los marcadores

---

## Auditoría en Este Proyecto

### Archivos con $wpdb->prepare()

Actualmente se encontraron las siguientes llamadas en:

#### `/includes/class-false-positive-manager.php`

| Línea | Consulta | Marcadores | Argumentos | Estado |
|-------|----------|------------|------------|--------|
| 121-126 | `SELECT id FROM... WHERE plugin_file = %s AND file_path = %s AND issue_hash = %s` | 3 (%s, %s, %s) | 3 | ✅ OK |
| 193-199 | `SELECT issue_hash, issue_type, file_path... WHERE plugin_file = %s` | 1 (%s) | 1 | ✅ OK |
| 201-208 | `SELECT issue_hash, issue_type... WHERE plugin_file = %s AND file_path = %s` | 2 (%s, %s) | 2 | ✅ OK |
| 235-240 | `SELECT id FROM... WHERE plugin_file = %s AND issue_hash = %s` | 2 (%s, %s) | 2 | ✅ OK |
| 242-248 | `SELECT id FROM... WHERE plugin_file = %s AND file_path = %s AND issue_hash = %s` | 3 (%s, %s, %s) | 3 | ✅ OK |
| 487-490 | `SELECT plugin_file FROM... WHERE id = %d` | 1 (%d) | 1 | ✅ OK |
| 546-549 | `SELECT issue_hash FROM... WHERE plugin_file = %s` | 1 (%s) | 1 | ✅ OK |
| 594-597 | `SELECT issue_hash FROM... WHERE plugin_file = %s` | 1 (%s) | 1 | ✅ OK |

**Estado actual**: ✅ Todas las llamadas son correctas

---

## Checklist para Nuevas Consultas

Antes de hacer commit de una nueva consulta con `$wpdb->prepare()`:

- [ ] Contar el número de marcadores (`%s`, `%d`, `%f`) en la consulta
- [ ] Contar el número de argumentos pasados después de la consulta
- [ ] Verificar que ambos números coincidan
- [ ] Verificar que el tipo de marcador sea adecuado para el tipo de dato
- [ ] Probar la consulta en entorno de desarrollo con `WP_DEBUG=true`

---

## Referencias

- [Documentación oficial de $wpdb->prepare()](https://developer.wordpress.org/reference/classes/wpdb/prepare/)
- [Debugging en WordPress](https://developer.wordpress.org/advanced-administration/debug/debug-wordpress/)

---

**Nota**: Este documento debe ser revisado cada vez que se agreguen nuevas consultas a la base de datos.
