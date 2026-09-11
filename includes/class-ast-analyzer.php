<?php
/**
 * Aegis Day0 - AST-Based Security Analyzer
 *
 * Analizador estático avanzado usando PHP-Parser (nikic/php-parser)
 * para detectar patrones de vulnerabilidad mediante análisis del árbol sintáctico abstracto (AST)
 * 
 * Este enfoque proporciona mayor precisión que el análisis por tokens, permitiendo:
 * - Seguimiento preciso de flujo de datos
 * - Detección contextual de variables sanitizadas
 * - Identificación de cadenas de ejecución peligrosa
 * - Análisis de scope y namespace
 *
 * @package Aegis_Day0
 * @since 0.4
 */

if (!defined('ABSPATH')) {
    exit;
}

// Cargar autoload manual de PhpParser
require_once __DIR__ . '/../lib/autoload.php';

use PhpParser\Error;
use PhpParser\Node;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitor\NameResolver;
use PhpParser\ParserFactory;
use PhpParser\ErrorHandler\Collecting;

class Aegis_AST_Analyzer {

    /**
     * Funciones peligrosas clasificadas por tipo de vulnerabilidad
     */
    private $dangerous_functions = [
        // Ejecución de código - CRITICAL
        'eval' => ['type' => 'code_execution', 'severity' => 'critical', 'false_positive_risk' => 'low'],
        'assert' => ['type' => 'code_execution', 'severity' => 'high', 'false_positive_risk' => 'medium'],
        
        // Ejecución de comandos del sistema - CRITICAL/HIGH
        'exec' => ['type' => 'command_execution', 'severity' => 'critical', 'false_positive_risk' => 'low'],
        'system' => ['type' => 'command_execution', 'severity' => 'high', 'false_positive_risk' => 'medium'],
        'shell_exec' => ['type' => 'command_execution', 'severity' => 'high', 'false_positive_risk' => 'medium'],
        'passthru' => ['type' => 'command_execution', 'severity' => 'high', 'false_positive_risk' => 'medium'],
        'popen' => ['type' => 'command_execution', 'severity' => 'high', 'false_positive_risk' => 'medium'],
        'proc_open' => ['type' => 'command_execution', 'severity' => 'high', 'false_positive_risk' => 'medium'],
        'proc_get_status' => ['type' => 'command_execution', 'severity' => 'medium', 'false_positive_risk' => 'high'],
        
        // Inclusión dinámica de archivos - HIGH
        'include' => ['type' => 'file_inclusion', 'severity' => 'high', 'false_positive_risk' => 'medium'],
        'include_once' => ['type' => 'file_inclusion', 'severity' => 'high', 'false_positive_risk' => 'medium'],
        'require' => ['type' => 'file_inclusion', 'severity' => 'high', 'false_positive_risk' => 'medium'],
        'require_once' => ['type' => 'file_inclusion', 'severity' => 'high', 'false_positive_risk' => 'medium'],
        
        // Deserialización insegura - CRITICAL
        'unserialize' => ['type' => 'insecure_deserialization', 'severity' => 'critical', 'false_positive_risk' => 'low'],
        
        // Funciones dinámicas - HIGH
        'call_user_func' => ['type' => 'dynamic_call', 'severity' => 'high', 'false_positive_risk' => 'medium'],
        'call_user_func_array' => ['type' => 'dynamic_call', 'severity' => 'high', 'false_positive_risk' => 'medium'],
        'create_function' => ['type' => 'code_execution', 'severity' => 'high', 'false_positive_risk' => 'low'],
        
        // Acceso a archivos - MEDIUM
        'file_get_contents' => ['type' => 'file_access', 'severity' => 'medium', 'false_positive_risk' => 'high'],
        'fopen' => ['type' => 'file_access', 'severity' => 'medium', 'false_positive_risk' => 'high'],
        'file_put_contents' => ['type' => 'file_access', 'severity' => 'medium', 'false_positive_risk' => 'high'],
        
        // SQL directo (potencial inyección) - HIGH
        'mysqli_query' => ['type' => 'sql_query', 'severity' => 'medium', 'false_positive_risk' => 'high'],
        'mysqli_real_query' => ['type' => 'sql_query', 'severity' => 'medium', 'false_positive_risk' => 'high'],
        'pdo_query' => ['type' => 'sql_query', 'severity' => 'medium', 'false_positive_risk' => 'high'],
        'mysql_query' => ['type' => 'sql_query', 'severity' => 'high', 'false_positive_risk' => 'medium'],
        
        // Output sin escapar (XSS potencial) - MEDIUM
        'echo' => ['type' => 'output', 'severity' => 'low', 'false_positive_risk' => 'high'],
        'print' => ['type' => 'output', 'severity' => 'low', 'false_positive_risk' => 'high'],
    ];

    /**
     * Métodos peligrosos de clases (ej. $wpdb->query)
     */
    private $dangerous_methods = [
        // WordPress WPDB methods
        'query' => ['type' => 'sql_query', 'severity' => 'high', 'class' => 'wpdb', 'false_positive_risk' => 'medium'],
        'get_var' => ['type' => 'sql_query', 'severity' => 'high', 'class' => 'wpdb', 'false_positive_risk' => 'medium'],
        'get_row' => ['type' => 'sql_query', 'severity' => 'high', 'class' => 'wpdb', 'false_positive_risk' => 'medium'],
        'get_col' => ['type' => 'sql_query', 'severity' => 'high', 'class' => 'wpdb', 'false_positive_risk' => 'medium'],
        'get_results' => ['type' => 'sql_query', 'severity' => 'high', 'class' => 'wpdb', 'false_positive_risk' => 'medium'],
        'insert' => ['type' => 'sql_query', 'severity' => 'medium', 'class' => 'wpdb', 'false_positive_risk' => 'high'],
        'update' => ['type' => 'sql_query', 'severity' => 'medium', 'class' => 'wpdb', 'false_positive_risk' => 'high'],
        'delete' => ['type' => 'sql_query', 'severity' => 'medium', 'class' => 'wpdb', 'false_positive_risk' => 'high'],
        'replace' => ['type' => 'sql_query', 'severity' => 'medium', 'class' => 'wpdb', 'false_positive_risk' => 'high'],
    ];

    /**
     * Funciones de sanitización reconocidas
     */
    private $sanitizing_functions = [
        // WordPress sanitization
        'sanitize_text_field',
        'sanitize_textarea_field',
        'sanitize_key',
        'sanitize_email',
        'sanitize_file_name',
        'sanitize_path',
        'sanitize_title',
        'sanitize_user',
        'wp_kses',
        'wp_kses_post',
        'wp_kses_data',
        'esc_html',
        'esc_attr',
        'esc_url',
        'esc_js',
        'esc_textarea',
        
        // PHP type casting / validation
        'intval',
        'floatval',
        'doubleval',
        'boolval',
        'absint',
        'is_numeric',
        'ctype_digit',
        'filter_var',
        'filter_input',
        
        // WordPress security
        'check_admin_referer',
        'wp_verify_nonce',
        'wp_create_nonce',
    ];

    /**
     * Superglobals que indican input de usuario
     */
    private $superglobals = [
        '_GET',
        '_POST',
        '_REQUEST',
        '_COOKIE',
        '_SERVER',
        '_FILES',
        '_ENV',
    ];

    /**
     * Funciones de escaping para SQL
     */
    private $sql_sanitizing_functions = [
        'esc_sql',
        'wpdb::prepare',
        'mysqli_real_escape_string',
        'mysqli_escape_string',
        'mysql_real_escape_string',
        'addslashes',
    ];

    /**
     * Parser instance
     */
    private $parser;

    /**
     * Name resolver for namespace handling
     */
    private $nameResolver;

    /**
     * Node traverser
     */
    private $traverser;

    /**
     * Current file being analyzed
     */
    private $current_file;

    /**
     * Collected alerts
     */
    private $alerts;

    /**
     * Constructor - inicializa el parser y traverser
     */
    public function __construct() {
        $parserFactory = new ParserFactory();
        $this->parser = $parserFactory->createForHostVersion();
        $this->nameResolver = new NameResolver();
        
        $this->traverser = new NodeTraverser();
        $this->traverser->addVisitor($this->nameResolver);
        
        $this->alerts = [];
    }

    /**
     * Obtiene el archivo actual
     * 
     * @return string Ruta del archivo actual
     */
    public function get_current_file() {
        return $this->current_file;
    }

    /**
     * Analiza un archivo PHP usando AST
     *
     * @param string $file_path Ruta del archivo a analizar
     * @return array Alertas encontradas
     */
    public function analyze_file($file_path) {
        $this->current_file = $file_path;
        $this->alerts = [];

        if (!file_exists($file_path) || !is_readable($file_path)) {
            return $this->alerts;
        }

        $content = @file_get_contents($file_path);
        if ($content === false || empty($content)) {
            return $this->alerts;
        }

        // Solo analizar archivos PHP
        if (!$this->is_php_file($content)) {
            return $this->alerts;
        }

        try {
            $errorHandler = new Collecting();
            $stmts = $this->parser->parse($content, $errorHandler);

            if ($stmts === null) {
                // Parser no pudo recuperar del error
                return $this->alerts;
            }

            // Recorrer el AST y buscar patrones peligrosos
            $this->traverser->addVisitor(new Aegis_AST_Visitor($this));
            $this->traverser->traverse($stmts);

        } catch (Error $e) {
            // Error de parsing - registrar pero continuar
            error_log('Aegis AST Analyzer - Parse error in ' . $file_path . ': ' . $e->getMessage());
        } catch (Exception $e) {
            error_log('Aegis AST Analyzer - Exception in ' . $file_path . ': ' . $e->getMessage());
        }

        return $this->alerts;
    }

    /**
     * Verifica si el contenido parece ser código PHP
     */
    private function is_php_file($content) {
        return strpos($content, '<?php') !== false || strpos($content, '<?') !== false;
    }

    /**
     * Agrega una alerta desde el visitor
     *
     * @param array $alert Datos de la alerta
     */
    public function add_alert($alert) {
        $this->alerts[] = $alert;
    }

    /**
     * Obtiene información de una función peligrosa
     *
     * @param string $function_name Nombre de la función
     * @return array|null Información de la función o null si no es peligrosa
     */
    public function get_function_info($function_name) {
        $func_lower = strtolower($function_name);
        return isset($this->dangerous_functions[$func_lower]) 
            ? $this->dangerous_functions[$func_lower] 
            : null;
    }

    /**
     * Obtiene información de un método peligroso de clase
     *
     * @param string $method_name Nombre del método
     * @param string|null $class_name Nombre de la clase (opcional)
     * @return array|null Información del método o null si no es peligroso
     */
    public function get_method_info($method_name, $class_name = null) {
        $method_lower = strtolower($method_name);
        
        if (!isset($this->dangerous_methods[$method_lower])) {
            return null;
        }
        
        $method_info = $this->dangerous_methods[$method_lower];
        
        // Si se especifica clase, verificar que coincida
        if ($class_name !== null) {
            $class_lower = strtolower($class_name);
            if (isset($method_info['class']) && strtolower($method_info['class']) !== $class_lower) {
                return null;
            }
        }
        
        return $method_info;
    }

    /**
     * Verifica si una función es de sanitización
     *
     * @param string $function_name Nombre de la función
     * @return bool True si es función sanitizadora
     */
    public function is_sanitizing_function($function_name) {
        return in_array(strtolower($function_name), $this->sanitizing_functions, true);
    }

    /**
     * Verifica si una función es de sanitización SQL
     *
     * @param string $function_name Nombre de la función
     * @return bool True si es función sanitizadora de SQL
     */
    public function is_sql_sanitizing_function($function_name) {
        return in_array(strtolower($function_name), $this->sql_sanitizing_functions, true);
    }

    /**
     * Verifica si un nodo representa acceso a superglobal
     *
     * @param Node $node Nodo a verificar
     * @return bool True si es acceso a superglobal
     */
    public function is_superglobal_access(Node $node) {
        if ($node instanceof Node\Expr\ArrayDimFetch && $node->var instanceof Node\Expr\Variable) {
            $var_name = $node->var->name;
            if (is_string($var_name) && in_array($var_name, $this->superglobals, true)) {
                return true;
            }
        }
        
        if ($node instanceof Node\Expr\Variable && is_string($node->name)) {
            if (in_array($node->name, $this->superglobals, true)) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * Obtiene el nombre de una variable desde un nodo
     *
     * @param Node $node Nodo a analizar
     * @return string|null Nombre de la variable o null
     */
    public function get_variable_name(Node $node) {
        if ($node instanceof Node\Expr\Variable && is_string($node->name)) {
            return '$' . $node->name;
        }
        
        if ($node instanceof Node\Expr\ArrayDimFetch && $node->var instanceof Node\Expr\Variable) {
            $var_name = $node->var->name;
            if (is_string($var_name)) {
                $key = '';
                if ($node->dim instanceof Node\Scalar\String_) {
                    $key = "['" . $node->dim->value . "']";
                } elseif ($node->dim instanceof Node\Scalar\LNumber) {
                    $key = '[' . $node->dim->value . ']';
                }
                return '$' . $var_name . $key;
            }
        }
        
        return null;
    }

    /**
     * Obtiene contexto de código para una línea específica
     *
     * @param string $content Contenido del archivo
     * @param int $line_number Número de línea
     * @return string Contexto del código
     */
    private function get_code_context($content, $line_number) {
        $lines = explode("\n", $content);
        $index = $line_number - 1;

        if (!isset($lines[$index])) {
            return '';
        }

        $context_line = trim($lines[$index]);

        // Limitar longitud
        if (strlen($context_line) > 150) {
            $context_line = substr($context_line, 0, 147) . '...';
        }

        return htmlspecialchars($context_line, ENT_QUOTES, 'UTF-8');
    }

    /**
     * Obtiene recomendación basada en el tipo de vulnerabilidad
     *
     * @param string $type Tipo de vulnerabilidad
     * @param string $function Función involucrada
     * @return string Recomendación
     */
    public function get_recommendation($type, $function) {
        $recommendations = [
            'code_execution' => [
                'eval' => __('NUNCA usar eval() con input de usuario. Refactorizar para evitar ejecución dinámica.', 'aegis-day0'),
                'assert' => __('No usar assert() con expresiones dinámicas en producción. Usar excepciones.', 'aegis-day0'),
                'create_function' => __('Obsoleto desde PHP 7.2. Usar funciones anónimas (closures).', 'aegis-day0'),
            ],
            'command_execution' => [
                'exec' => __('Usar escapeshellarg() para todos los argumentos. Implementar whitelist de comandos.', 'aegis-day0'),
                'system' => __('Evitar cuando sea posible. Usar funciones específicas de WordPress.', 'aegis-day0'),
                'shell_exec' => __('Sanitizar con escapeshellarg(). Considerar wp_safe_remote_get() para HTTP.', 'aegis-day0'),
                'passthru' => __('Validar exhaustivamente los argumentos. Usar output buffering con precaución.', 'aegis-day0'),
                'popen' => __('Cerrar siempre el handle con pclose(). Validar comandos permitidos.', 'aegis-day0'),
                'proc_open' => __('Usar solo con comandos predefinidos. Nunca con input de usuario directo.', 'aegis-day0'),
            ],
            'file_inclusion' => [
                'default' => __('Usar rutas absolutas con realpath(). Implementar whitelist de archivos incluibles.', 'aegis-day0'),
            ],
            'insecure_deserialization' => [
                'unserialize' => __('Reemplazar con json_decode() cuando sea posible. Usar parámetro allowed_classes en PHP 7+. ', 'aegis-day0'),
            ],
            'dynamic_call' => [
                'call_user_func' => __('Validar que el callback apunte a funciones seguras. Evitar callbacks dinámicos de usuario.', 'aegis-day0'),
            ],
            'file_access' => [
                'file_get_contents' => __('Validar URLs con wp_http_validate_url(). Usar filtros de contexto stream.', 'aegis-day0'),
                'fopen' => __('Validar rutas con realpath(). Restringir a directorios permitidos (open_basedir).', 'aegis-day0'),
            ],
            'sql_query' => [
                'default' => __('Usar prepared statements con $wpdb->prepare(). NUNCA concatenar variables directamente.', 'aegis-day0'),
            ],
            'output' => [
                'default' => __('Escapar output con esc_html(), esc_attr(), esc_url() según el contexto.', 'aegis-day0'),
            ],
        ];

        if (isset($recommendations[$type][$function])) {
            return $recommendations[$type][$function];
        }
        
        if (isset($recommendations[$type]['default'])) {
            return $recommendations[$type]['default'];
        }

        return __('Verificar documentación y aplicar principio de mínimo privilegio.', 'aegis-day0');
    }

    /**
     * Analiza múltiples archivos
     *
     * @param array $files Lista de rutas de archivos
     * @return array Resultados consolidados
     */
    public function analyze_files($files) {
        $all_alerts = [];
        $stats = [
            'total_files' => count($files),
            'scanned_files' => 0,
            'total_alerts' => 0,
            'by_severity' => ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0],
            'by_type' => []
        ];

        foreach ($files as $file) {
            if (!file_exists($file)) {
                continue;
            }

            $stats['scanned_files']++;
            $alerts = $this->analyze_file($file);

            foreach ($alerts as $alert) {
                $severity = strtolower($alert['severity']);
                if (isset($stats['by_severity'][$severity])) {
                    $stats['by_severity'][$severity]++;
                }
                
                $type = $alert['type'] ?? 'unknown';
                if (!isset($stats['by_type'][$type])) {
                    $stats['by_type'][$type] = 0;
                }
                $stats['by_type'][$type]++;
            }

            $stats['total_alerts'] += count($alerts);
            $all_alerts = array_merge($all_alerts, $alerts);
        }

        return [
            'alerts' => $all_alerts,
            'stats' => $stats
        ];
    }
}

/**
 * Node Visitor para detectar patrones peligrosos en el AST
 */
class Aegis_AST_Visitor extends \PhpParser\NodeVisitorAbstract {
    
    /**
     * Referencia al analizador principal
     */
    private $analyzer;

    /**
     * Variables rastreadas como "sanitizadas"
     */
    private $sanitized_vars = [];

    /**
     * Variables rastreadas como "input de usuario"
     */
    private $user_input_vars = [];

    /**
     * Constructor
     *
     * @param Aegis_AST_Analyzer $analyzer Instancia del analizador
     */
    public function __construct(Aegis_AST_Analyzer $analyzer) {
        $this->analyzer = $analyzer;
    }

    /**
     * Se llama antes de recorrer los nodos
     */
    public function beforeTraverse(array $nodes) {
        $this->sanitized_vars = [];
        $this->user_input_vars = [];
        return null;
    }

    /**
     * Procesa cada nodo del AST
     */
    public function enterNode(Node $node) {
        // Detectar asignación desde superglobals (input de usuario)
        $this->trackUserInput($node);
        
        // Detectar llamadas a funciones sanitizadoras
        $this->trackSanitization($node);
        
        // Detectar llamadas a funciones peligrosas
        if ($node instanceof Node\Expr\FuncCall) {
            $this->analyzeFunctionCall($node);
        }
        
        // Detectar métodos peligrosos en objetos (ej. $wpdb->get_var)
        if ($node instanceof Node\Expr\MethodCall) {
            $this->analyzeMethodCall($node);
        }
        
        // Detectar construcciones de lenguaje peligrosas
        if ($node instanceof Node\Stmt\Expression) {
            $this->analyzeExpression($node);
        }
        
        // Detectar echo/print con variables potencialmente peligrosas
        if ($node instanceof Node\Stmt\Echo_) {
            $this->analyzeEcho($node);
        }
        
        // Detectar hooks de AJAX (wp_ajax_nopriv_ y wp_ajax_)
        if ($node instanceof Node\Expr\FuncCall && $node->name instanceof Node\Name) {
            $func_name = $node->name->toString();
            if ($func_name === 'add_action') {
                $this->analyzeAjaxHooks($node);
            }
        }

        return null;
    }

    /**
     * Rastrea variables que reciben input de usuario
     */
    private function trackUserInput(Node $node) {
        if ($node instanceof Node\Expr\Assign) {
            // Verificar si el valor viene de un superglobal
            if ($this->analyzer->is_superglobal_access($node->expr)) {
                $var_name = $this->analyzer->get_variable_name($node->var);
                if ($var_name) {
                    $this->user_input_vars[] = $var_name;
                }
            }
            
            // Propagar marca de user_input en asignaciones simples
            if ($node->expr instanceof Node\Expr\Variable) {
                $expr_name = $this->analyzer->get_variable_name($node->expr);
                if ($expr_name && in_array($expr_name, $this->user_input_vars, true)) {
                    $var_name = $this->analyzer->get_variable_name($node->var);
                    if ($var_name) {
                        $this->user_input_vars[] = $var_name;
                    }
                }
            }
        }
    }

    /**
     * Rastrea variables sanitizadas
     */
    private function trackSanitization(Node $node) {
        if ($node instanceof Node\Expr\Assign && $node->expr instanceof Node\Expr\FuncCall) {
            $func_name = $node->expr->name;
            if ($func_name instanceof Node\Name) {
                $func_str = $func_name->toString();
                if ($this->analyzer->is_sanitizing_function($func_str)) {
                    $var_name = $this->analyzer->get_variable_name($node->var);
                    if ($var_name) {
                        $this->sanitized_vars[] = $var_name;
                    }
                }
            }
        }
    }

    /**
     * Analiza llamada a función
     */
    private function analyzeFunctionCall(Node\Expr\FuncCall $node) {
        $func_name = $node->name;
        
        if (!($func_name instanceof Node\Name)) {
            return;
        }

        $func_str = $func_name->toString();
        $func_info = $this->analyzer->get_function_info($func_str);

        if (!$func_info) {
            return;
        }

        $line = $node->getLine();
        $uses_user_input = false;
        $is_sanitized = false;

        // Analizar argumentos
        foreach ($node->args as $arg) {
            if ($arg instanceof Node\Arg) {
                $value = $arg->value;
                
                // Verificar si usa input de usuario
                if ($this->analyzer->is_superglobal_access($value)) {
                    $uses_user_input = true;
                }
                
                if ($value instanceof Node\Expr\Variable) {
                    $var_name = $this->analyzer->get_variable_name($value);
                    if ($var_name && in_array($var_name, $this->user_input_vars, true)) {
                        $uses_user_input = true;
                    }
                    if ($var_name && in_array($var_name, $this->sanitized_vars, true)) {
                        $is_sanitized = true;
                    }
                }
                
                // Verificar si el argumento está siendo sanitizado inline
                if ($value instanceof Node\Expr\FuncCall && $value->name instanceof Node\Name) {
                    if ($this->analyzer->is_sanitizing_function($value->name->toString())) {
                        $is_sanitized = true;
                    }
                }
            }
        }

        // Calcular severidad ajustada
        $adjusted_severity = $func_info['severity'];
        $false_positive_risk = $func_info['false_positive_risk'];

        if ($is_sanitized) {
            $adjusted_severity = 'low';
            $false_positive_risk = 'high';
        } elseif ($uses_user_input) {
            // Mantener o aumentar severidad si hay input de usuario directo
            if ($func_info['severity'] === 'medium') {
                $adjusted_severity = 'high';
            }
            $false_positive_risk = 'low';
        }

        // Generar alerta
        if ($adjusted_severity !== 'low' || $uses_user_input) {
            $this->analyzer->add_alert([
                'type' => $func_info['type'],
                'function' => $func_str,
                'file' => $this->analyzer->get_current_file(),
                'line' => $line,
                'severity' => ucfirst($adjusted_severity),
                'false_positive_risk' => $false_positive_risk,
                'description' => sprintf(
                    __('Función peligrosa detectada: %s(). %s', 'aegis-day0'),
                    $func_str,
                    $uses_user_input 
                        ? __('Usa input de usuario sin validación aparente.', 'aegis-day0')
                        : __('Verificar contexto de uso y permisos.', 'aegis-day0')
                ),
                'uses_user_input' => $uses_user_input,
                'is_sanitized' => $is_sanitized,
                'recommendation' => $this->analyzer->get_recommendation($func_info['type'], $func_str)
            ]);
        }
    }

    /**
     * Analiza expresiones (para construcciones de lenguaje)
     */
    private function analyzeExpression(Node\Stmt\Expression $node) {
        $expr = $node->expr;
        
        // Detectar include/require dinámico
        if ($expr instanceof Node\Expr\Include_) {
            $this->analyzeInclude($expr);
        }
    }

    /**
     * Analiza inclusión de archivos
     */
    private function analyzeInclude(Node\Expr\Include_ $node) {
        $expr = $node->expr;
        $line = $node->getLine();
        
        $type_map = [
            Node\Expr\Include_::TYPE_INCLUDE => 'include',
            Node\Expr\Include_::TYPE_INCLUDE_ONCE => 'include_once',
            Node\Expr\Include_::TYPE_REQUIRE => 'require',
            Node\Expr\Include_::TYPE_REQUIRE_ONCE => 'require_once',
        ];
        
        $func_name = $type_map[$node->type] ?? 'include';
        $uses_dynamic = false;
        $uses_user_input = false;

        // Verificar si es una expresión dinámica (variable, concatenación, etc.)
        if ($expr instanceof Node\Expr\Variable) {
            $uses_dynamic = true;
            $var_name = $this->analyzer->get_variable_name($expr);
            if ($var_name && in_array($var_name, $this->user_input_vars, true)) {
                $uses_user_input = true;
            }
        } elseif ($expr instanceof Node\Expr\BinaryOp\Concat) {
            $uses_dynamic = true;
            if ($this->containsUserInput($expr)) {
                $uses_user_input = true;
            }
        }

        if ($uses_dynamic) {
            $severity = $uses_user_input ? 'critical' : 'high';
            $fp_risk = $uses_user_input ? 'low' : 'medium';

            $this->analyzer->add_alert([
                'type' => 'file_inclusion',
                'function' => $func_name,
                'file' => $this->analyzer->get_current_file(),
                'line' => $line,
                'severity' => ucfirst($severity),
                'false_positive_risk' => $fp_risk,
                'description' => sprintf(
                    __('Inclusión dinámica de archivos detectada: %s. %s', 'aegis-day0'),
                    $func_name,
                    $uses_user_input 
                        ? __('La ruta incluye input de usuario - RIESGO CRÍTICO de LFI/RFI.', 'aegis-day0')
                        : __('La ruta es dinámica - verificar origen de los datos.', 'aegis-day0')
                ),
                'uses_user_input' => $uses_user_input,
                'recommendation' => __('Usar rutas absolutas con realpath(). Implementar whitelist estricta de archivos.', 'aegis-day0')
            ]);
        }
    }

    /**
     * Analiza llamada a método de objeto (ej. $wpdb->get_var)
     */
    private function analyzeMethodCall(Node\Expr\MethodCall $node) {
        $method_name = $node->name;
        
        // Solo analizar si el nombre del método es un string
        if (!($method_name instanceof Node\Identifier)) {
            return;
        }
        
        $method_str = $method_name->toString();
        
        // Verificar si el objeto es una instancia de wpdb
        $var = $node->var;
        $is_wpdb = false;
        
        if ($var instanceof Node\Expr\Variable && is_string($var->name)) {
            // Verificar si es $wpdb
            if ($var->name === 'wpdb') {
                $is_wpdb = true;
            }
        }
        
        // Si no es wpdb, verificar por tipo inferido
        if (!$is_wpdb) {
            // Podríamos implementar type inference aquí en el futuro
            return;
        }
        
        // Obtener información del método peligroso
        $method_info = $this->analyzer->get_method_info($method_str, 'wpdb');
        
        if (!$method_info) {
            return;
        }
        
        $line = $node->getLine();
        $uses_user_input = false;
        $is_sanitized = false;
        
        // Analizar argumentos para SQL injection
        foreach ($node->args as $arg) {
            if ($arg instanceof Node\Arg) {
                $value = $arg->value;
                
                // Verificar si usa input de usuario directo
                if ($this->analyzer->is_superglobal_access($value)) {
                    $uses_user_input = true;
                }
                
                // Verificar variables
                if ($value instanceof Node\Expr\Variable) {
                    $var_name = $this->analyzer->get_variable_name($value);
                    if ($var_name) {
                        if (in_array($var_name, $this->user_input_vars, true)) {
                            $uses_user_input = true;
                        }
                        if (in_array($var_name, $this->sanitized_vars, true)) {
                            $is_sanitized = true;
                        }
                    }
                }
                
                // Verificar concatenaciones (SQL injection común)
                if ($value instanceof Node\Expr\BinaryOp\Concat) {
                    if ($this->containsUnsanitizedUserInput($value)) {
                        $uses_user_input = true;
                    }
                }
            }
        }
        
        // Calcular severidad ajustada
        $adjusted_severity = $method_info['severity'];
        $false_positive_risk = $method_info['false_positive_risk'];
        
        // Si hay concatenación con input de usuario, aumentar severidad
        if ($uses_user_input && !$is_sanitized) {
            if ($method_info['severity'] === 'medium') {
                $adjusted_severity = 'high';
            } elseif ($method_info['severity'] === 'high') {
                $adjusted_severity = 'critical';
            }
            $false_positive_risk = 'low';
        } elseif ($is_sanitized) {
            $adjusted_severity = 'low';
            $false_positive_risk = 'high';
        }
        
        // Generar alerta
        if ($adjusted_severity !== 'low' || $uses_user_input) {
            $description = sprintf(
                __('Método %s::%s() detectado. %s', 'aegis-day0'),
                'wpdb',
                $method_str,
                $uses_user_input 
                    ? __('Posible uso de input de usuario sin sanitización - Riesgo de SQL Injection.', 'aegis-day0')
                    : __('Verificar que se use $wpdb->prepare() para consultas con variables.', 'aegis-day0')
            );
            
            $recommendation = $uses_user_input && !$is_sanitized
                ? __('USAR $wpdb->prepare() para todas las consultas con variables. NUNCA concatenar $_GET/$_POST directamente.', 'aegis-day0')
                : __('Asegurar que todas las variables estén sanitizadas antes de usarlas en consultas SQL.', 'aegis-day0');
            
            $this->analyzer->add_alert([
                'type' => $method_info['type'],
                'function' => '$wpdb->' . $method_str,
                'file' => $this->analyzer->get_current_file(),
                'line' => $line,
                'severity' => ucfirst($adjusted_severity),
                'false_positive_risk' => $false_positive_risk,
                'description' => $description,
                'uses_user_input' => $uses_user_input,
                'is_sanitized' => $is_sanitized,
                'recommendation' => $recommendation
            ]);
        }
    }

    /**
     * Analiza sentencias echo para XSS
     */
    private function analyzeEcho(Node\Stmt\Echo_ $node) {
        foreach ($node->exprs as $expr) {
            $uses_unsanitized_input = false;
            $line = $node->getLine();

            // Verificar si es output directo de superglobal
            if ($this->analyzer->is_superglobal_access($expr)) {
                $uses_unsanitized_input = true;
            }

            // Verificar variables
            if ($expr instanceof Node\Expr\Variable) {
                $var_name = $this->analyzer->get_variable_name($expr);
                if ($var_name) {
                    if (in_array($var_name, $this->user_input_vars, true) && 
                        !in_array($var_name, $this->sanitized_vars, true)) {
                        $uses_unsanitized_input = true;
                    }
                }
            }

            // Verificar concatenaciones
            if ($expr instanceof Node\Expr\BinaryOp\Concat) {
                if ($this->containsUnsanitizedUserInput($expr)) {
                    $uses_unsanitized_input = true;
                }
            }

            if ($uses_unsanitized_input) {
                $this->analyzer->add_alert([
                    'type' => 'potential_xss',
                    'function' => 'echo',
                    'file' => $this->analyzer->get_current_file(),
                    'line' => $line,
                    'severity' => 'High',
                    'false_positive_risk' => 'medium',
                    'description' => __('Output directo de input de usuario sin escaping aparente - Riesgo de XSS.', 'aegis-day0'),
                    'recommendation' => __('Usar esc_html(), esc_attr(), o esc_url() según el contexto de output.', 'aegis-day0')
                ]);
            }
        }
    }

    /**
     * Verifica si una expresión de concatenación contiene input de usuario
     */
    private function containsUserInput(Node $node) {
        if ($node instanceof Node\Expr\Variable) {
            $var_name = $this->analyzer->get_variable_name($node);
            return $var_name && in_array($var_name, $this->user_input_vars, true);
        }
        
        if ($node instanceof Node\Expr\BinaryOp\Concat) {
            return $this->containsUserInput($node->left) || $this->containsUserInput($node->right);
        }
        
        return false;
    }

    /**
     * Analiza hooks de AJAX para detectar posibles vulnerabilidades
     */
    private function analyzeAjaxHooks(Node\Expr\FuncCall $node) {
        // Verificar si tiene al menos un argumento
        if (empty($node->args)) {
            return;
        }
        
        $first_arg = $node->args[0]->value;
        
        // Obtener el nombre del hook
        $hook_name = '';
        if ($first_arg instanceof Node\Scalar\String_) {
            $hook_name = $first_arg->value;
        }
        
        if (empty($hook_name)) {
            return;
        }
        
        $line = $node->getLine();
        
        // Detectar wp_ajax_nopriv_ (endpoints públicos sin autenticación)
        if (strpos($hook_name, 'wp_ajax_nopriv_') === 0) {
            $action_name = str_replace('wp_ajax_nopriv_', '', $hook_name);
            $this->analyzer->add_alert([
                'type' => 'ajax_security',
                'function' => 'add_action',
                'file' => $this->analyzer->get_current_file(),
                'line' => $line,
                'severity' => 'Medium',
                'false_positive_risk' => 'medium',
                'description' => sprintf(
                    __('Endpoint AJAX público detectado: %s. No requiere autenticación.', 'aegis-day0'),
                    $action_name
                ),
                'recommendation' => __('Verificar que este endpoint no realice operaciones sensibles. Considerar usar wp_ajax_ en su lugar e implementar validación de nonce y capacidades.', 'aegis-day0')
            ]);
        }
        
        // Detectar wp_ajax_ (endpoints autenticados - recordar verificar nonce)
        if (strpos($hook_name, 'wp_ajax_') === 0 && strpos($hook_name, 'wp_ajax_nopriv_') !== 0) {
            $action_name = str_replace('wp_ajax_', '', $hook_name);
            $this->analyzer->add_alert([
                'type' => 'ajax_security',
                'function' => 'add_action',
                'file' => $this->analyzer->get_current_file(),
                'line' => $line,
                'severity' => 'Low',
                'false_positive_risk' => 'high',
                'description' => sprintf(
                    __('Hook AJAX autenticado detectado: %s. Verificar implementación de seguridad.', 'aegis-day0'),
                    $action_name
                ),
                'recommendation' => __('Asegurar que el callback verifique nonce (wp_verify_nonce) y capacidades (current_user_can).', 'aegis-day0')
            ]);
        }
    }

    /**
     * Verifica si una expresión contiene input de usuario no sanitizado
     */
    private function containsUnsanitizedUserInput(Node $node) {
        if ($node instanceof Node\Expr\Variable) {
            $var_name = $this->analyzer->get_variable_name($node);
            return $var_name && 
                   in_array($var_name, $this->user_input_vars, true) && 
                   !in_array($var_name, $this->sanitized_vars, true);
        }
        
        if ($node instanceof Node\Expr\BinaryOp\Concat) {
            return $this->containsUnsanitizedUserInput($node->left) || 
                   $this->containsUnsanitizedUserInput($node->right);
        }
        
        if ($this->analyzer->is_superglobal_access($node)) {
            return true;
        }
        
        return false;
    }
}
