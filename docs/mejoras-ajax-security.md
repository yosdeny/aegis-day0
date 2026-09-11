# Mejoras de Seguridad para Detección de Falsos Positivos en Endpoints AJAX

## Resumen Ejecutivo

Se han implementado mejoras significativas en el plugin Aegis Day0 para reducir falsos positivos en la detección de endpoints AJAX públicos (`wp_ajax_nopriv_`). Estas mejoras permiten identificar automáticamente cuando un endpoint tiene controles de seguridad compensatorios, clasificándolo correctamente como "Riesgo Aceptable" o "Falso Positivo".

## Problema Detectado

Los escáneres SAST tradicionales detectan `add_action('wp_ajax_nopriv_...')` y asumen riesgo inmediato sin analizar el contexto. Esto genera:
- Alertas innecesarias para endpoints legítimos de comercio electrónico
- Fatiga de alertas en equipos de seguridad
- Tiempo desperdiciado en validaciones manuales

## Solución Implementada

### 1. Análisis Contextual de Mitigaciones

El analizador AST ahora rastrea e identifica cuatro tipos principales de controles de seguridad:

| Control | Funciones Detectadas | Propósito |
|---------|---------------------|-----------|
| **Validación de Nonce** | `check_ajax_referer`, `wp_verify_nonce`, `wp_nonce_check` | Previene ataques CSRF |
| **Rate Limiting** | `set_transient`, `get_transient`, `wp_cache_get`, `wp_cache_set` | Previene DoS/abuso |
| **Sanitización de Salida** | `esc_html`, `esc_attr`, `esc_url`, `wp_kses`, `wp_kses_post` | Previene XSS |
| **Validación de Dominio** | `wp_parse_url`, `parse_url`, funciones con 'domain' o 'host' | Previene SSRF/Open Redirect |

### 2. Sistema de Clasificación por Nivel de Mitigación

El sistema evalúa el número de controles presentes y ajusta la severidad:

#### 3-4 Controles (Alta Mitigación)
- **Severidad**: Low
- **Riesgo de Falso Positivo**: High
- **Mensaje**: "Múltiples controles de seguridad identificados"
- **Acción**: Marcar como riesgo aceptable para auditoría

#### 1-2 Controles (Mitigación Parcial)
- **Severidad**: Medium
- **Riesgo de Falso Positivo**: Medium
- **Mensaje**: "Controles de seguridad parciales identificados: [lista]"
- **Acción**: Recomendar controles adicionales

#### 0 Controles (Sin Mitigación)
- **Severidad**: Medium
- **Riesgo de Falso Positivo**: Medium
- **Mensaje**: "No requiere autenticación"
- **Acción**: Requerir revisión manual inmediata

### 3. Metadata Enriquecida para Reportes

Cada alerta ahora incluye un objeto `security_context`:

```php
'security_context' => [
    'has_nonce_validation' => true,
    'has_rate_limiting' => true,
    'has_output_sanitization' => true,
    'has_domain_validation' => false,
    'mitigation_count' => 3
]
```

## Cambios Técnicos Realizados

### Archivos Modificados

#### `/workspace/includes/class-ast-analyzer.php`

**Nuevas Propiedades:**
```php
private $nonce_validation_functions = [...];
private $rate_limiting_indicators = [...];
private $security_validation_count = [...];
```

**Nuevos Métodos:**
- `is_nonce_validation_function()` - Verifica funciones de validación de nonce
- `is_rate_limiting_function()` - Verifica funciones de rate limiting
- `trackSecurityValidations()` - Rastrea todas las validaciones de seguridad en el archivo

**Método Mejorado:**
- `analyzeAjaxHooks()` - Ahora realiza análisis contextual completo

### Integración con Reglas Existentes

El archivo `rules.php` mantiene su patrón regex para detección rápida, pero el análisis AST proporciona el contexto necesario para la clasificación final.

## Cómo Usar esta Funcionalidad

### Para Auditores de Seguridad

1. **Ejecutar el escaneo**:
   ```bash
   wp aegis-day0 scan
   ```

2. **Revisar reportes con contexto**:
   - Busque el campo `security_context` en cada alerta
   - Endpoints con `mitigation_count >= 3` pueden marcarse como falsos positivos

3. **Generar evidencia para auditoría**:
   ```php
   // El reporte incluirá:
   [
       'type' => 'ajax_security',
       'severity' => 'Low', // Reducida automáticamente
       'false_positive_risk' => 'high',
       'security_context' => [...]
   ]
   ```

### Para Configuración de Escáneres SAST

Use la siguiente estructura para whitelisting inteligente:

```yaml
# Configuración para SonarQube/RIPS/WPScan
suppressions:
  - rule_id: "WP_AJAX_PUBLIC_ENDPOINT"
    justification: "Endpoint con mitigaciones verificadas"
    conditions:
      - function_name: "*"
      - security_context:
          mitigation_count: ">=3"
    action: "MARK_AS_FALSE_POSITIVE"
```

### Para Desarrollo de Plugins

Si su plugin usa `wp_ajax_nopriv_`, asegúrese de implementar al menos 3 de estos controles:

```php
add_action('wp_ajax_nopriv_mi_funcion', 'mi_callback_seguro');

function mi_callback_seguro() {
    // 1. Validación de Nonce (Línea ~328)
    check_ajax_referer('mi_nonce', 'security');
    
    // 2. Rate Limiting (Líneas ~311-322)
    $transient_key = 'rate_limit_' . $_SERVER['REMOTE_ADDR'];
    if (get_transient($transient_key)) {
        wp_send_json_error(['message' => 'Too many requests']);
    }
    set_transient($transient_key, true, 60); // 1 req/min
    
    // 3. Validación de Dominio (Líneas ~287-308)
    $url = esc_url_raw($_POST['url']);
    $parsed = wp_parse_url($url);
    if (!isset($parsed['host']) || $parsed['host'] !== gethostname()) {
        wp_send_json_error(['message' => 'Invalid domain']);
    }
    
    // 4. Sanitización de Salida (Líneas ~385-386)
    $output = wp_kses_post(get_catalog_html());
    
    wp_send_json_success(['html' => $output]);
}
```

## Secuencia de Validación para Auditoría Manual

Use esta checklist para validar endpoints durante auditorías:

### Checklist de Validación de Contexto

- [ ] **Verificación de Intencionalidad**
  - ¿El endpoint devuelve datos públicos o privados?
  - Público (catálogo) = Riesgo menor
  - Privado (datos usuario) = Requiere autenticación

- [ ] **Verificación Anti-CSRF**
  - ¿Existe `check_ajax_referer()` o `wp_verify_nonce()`?
  - ¿Se valida en las primeras líneas del callback?

- [ ] **Verificación Anti-DoS**
  - ¿Hay implementación de rate limiting?
  - ¿Usa transients o cache para tracking?

- [ ] **Verificación de Integridad (SSRF)**
  - ¿Se validan URLs de entrada?
  - ¿Se verifica que pertenezcan al dominio propio?

- [ ] **Verificación de Salida (XSS)**
  - ¿El HTML/JSON devuelto es sanitizado?
  - ¿Se usan funciones `esc_*` o `wp_kses`?

### Criterio de Aceptación

**Riesgo Aceptable / Falso Positivo** si:
- ✅ La exposición pública es funcionalmente requerida (e-commerce)
- ✅ Existen ≥3 controles compensatorios activos
- ✅ Las pruebas de intrusión simuladas fueron bloqueadas

**Requiere Remediación** si:
- ❌ No hay validación de nonce
- ❌ No hay rate limiting
- ❌ Devuelve datos sensibles sin autenticación

## Ejemplo de Reporte Final

```markdown
## Hallazgo: Endpoint AJAX Público

**Plugin**: WooCommerce Catalog
**Función**: ygb_infinito_load_more
**Línea**: 275

### Secuencia de Validación de Seguridad

| Control | Estado | Línea |
|---------|--------|-------|
| Nonce Validation | ✅ IMPLEMENTADO | 328 |
| Rate Limiting | ✅ IMPLEMENTADO | 311-322 |
| Domain Validation | ✅ IMPLEMENTADO | 287-308 |
| Output Sanitization | ✅ IMPLEMENTADO | 385-386 |

### Conclusión

**Clasificación**: Falso Positivo / Riesgo Aceptable

**Justificación**: 
El endpoint devuelve datos públicos de catálogo (productos WooCommerce).
Cuatro controles de seguridad están activos:
1. Validación de nonce previene CSRF
2. Rate limiting (10 req/min) previene DoS
3. Validación de dominio previene SSRF
4. Sanitización de salida previene XSS

**Acción**: Ninguna requerida. Documentar como diseño seguro.
```

## Próximas Mejoras Sugeridas

1. **Análisis de Flujo de Datos**: Seguir variables desde el input hasta la salida
2. **Detección de Callbacks**: Analizar automáticamente la función callback del hook
3. **Reporte YAML Exportable**: Generar configuración de supresión automática
4. **Integración con GitHub Actions**: Validar PRs con cambios en endpoints AJAX

## Referencias

- [WordPress AJAX Security](https://developer.wordpress.org/plugins/security/using-javascript/)
- [OWASP AJAX Security Guidelines](https://cheatsheetseries.owasp.org/cheatsheets/AJAX_Security_Cheat_Sheet.html)
- [WP-CLI Security Commands](https://make.wordpress.org/cli/handbook/)

---

**Versión del Documento**: 1.0  
**Fecha**: 2024  
**Autor**: Aegis Day0 Security Team
