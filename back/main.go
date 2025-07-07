package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"unicode"
)

// TokenType representa los tipos de tokens
type TokenType int

const (
	KEYWORD TokenType = iota
	OPERATOR
	LITERAL
	IDENTIFIER
	COMMENT
	WHITESPACE
	SEMICOLON
	COMMA
	PARENTHESIS
	UNKNOWN
)

// Token representa un token léxico
type Token struct {
	Type     TokenType `json:"type"`
	Value    string    `json:"value"`
	Position int       `json:"position"`
	TypeName string    `json:"typeName"`
}

// AnalysisResult contiene el resultado del análisis
type AnalysisResult struct {
	Tokens           []Token           `json:"tokens"`
	IsMalicious      bool              `json:"isMalicious"`
	Threats          []ThreatDetection `json:"threats"`
	SyntaxValid      bool              `json:"syntaxValid"`
	SyntaxErrors     []string          `json:"syntaxErrors"`
	QueryType        string            `json:"queryType"`
	RiskLevel        string            `json:"riskLevel"`
}

// ThreatDetection representa una amenaza detectada
type ThreatDetection struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Position    int    `json:"position"`
}

// SQLAnalyzer es el analizador principal
type SQLAnalyzer struct {
	keywords map[string]bool
	operators []string
}

// NewSQLAnalyzer crea una nueva instancia del analizador
func NewSQLAnalyzer() *SQLAnalyzer {
	keywords := map[string]bool{
		"SELECT": true, "FROM": true, "WHERE": true, "INSERT": true, "UPDATE": true,
		"DELETE": true, "CREATE": true, "DROP": true, "ALTER": true, "TABLE": true,
		"INDEX": true, "VIEW": true, "UNION": true, "JOIN": true, "INNER": true,
		"LEFT": true, "RIGHT": true, "OUTER": true, "ON": true, "GROUP": true,
		"ORDER": true, "BY": true, "HAVING": true, "LIMIT": true, "OFFSET": true,
		"AND": true, "OR": true, "NOT": true, "IN": true, "EXISTS": true,
		"LIKE": true, "BETWEEN": true, "IS": true, "NULL": true, "AS": true,
		"DISTINCT": true, "ALL": true, "TOP": true, "COUNT": true, "SUM": true,
		"AVG": true, "MIN": true, "MAX": true, "CASE": true, "WHEN": true,
		"THEN": true, "ELSE": true, "END": true, "IF": true, "EXEC": true,
		"EXECUTE": true, "DECLARE": true, "SET": true, "CAST": true, "CONVERT": true,
		"SUBSTRING": true, "CONCAT": true, "CHAR": true, "ASCII": true,
		"WAITFOR": true, "DELAY": true, "BENCHMARK": true, "SLEEP": true,
		"LOAD_FILE": true, "INTO": true, "OUTFILE": true, "DUMPFILE": true,
	}

	operators := []string{"=", "!=", "<>", "<", ">", "<=", ">=", "+", "-", "*", "/", "%", "||", "&&", "|", "&", "^", "~", "<<", ">>"}

	return &SQLAnalyzer{
		keywords:  keywords,
		operators: operators,
	}
}

// Tokenize realiza el análisis léxico
func (sa *SQLAnalyzer) Tokenize(query string) []Token {
	var tokens []Token
	query = strings.TrimSpace(query)
	i := 0

	for i < len(query) {
		// Saltar espacios en blanco
		if unicode.IsSpace(rune(query[i])) {
			start := i
			for i < len(query) && unicode.IsSpace(rune(query[i])) {
				i++
			}
			tokens = append(tokens, Token{
				Type:     WHITESPACE,
				Value:    query[start:i],
				Position: start,
				TypeName: "WHITESPACE",
			})
			continue
		}

		// Comentarios SQL (-- o /* */)
		if i < len(query)-1 && query[i:i+2] == "--" {
			start := i
			for i < len(query) && query[i] != '\n' && query[i] != '\r' {
				i++
			}
			tokens = append(tokens, Token{
				Type:     COMMENT,
				Value:    query[start:i],
				Position: start,
				TypeName: "COMMENT",
			})
			continue
		}

		if i < len(query)-1 && query[i:i+2] == "/*" {
			start := i
			i += 2
			for i < len(query)-1 && query[i:i+2] != "*/" {
				i++
			}
			if i < len(query)-1 {
				i += 2
			}
			tokens = append(tokens, Token{
				Type:     COMMENT,
				Value:    query[start:i],
				Position: start,
				TypeName: "COMMENT",
			})
			continue
		}

		// Literales de cadena
		if query[i] == '\'' || query[i] == '"' || query[i] == '`' {
			quote := query[i]
			start := i
			i++
			for i < len(query) && query[i] != quote {
				if query[i] == '\\' && i+1 < len(query) {
					i += 2
				} else {
					i++
				}
			}
			if i < len(query) {
				i++
			}
			tokens = append(tokens, Token{
				Type:     LITERAL,
				Value:    query[start:i],
				Position: start,
				TypeName: "LITERAL",
			})
			continue
		}

		// Números
		if unicode.IsDigit(rune(query[i])) {
			start := i
			for i < len(query) && (unicode.IsDigit(rune(query[i])) || query[i] == '.') {
				i++
			}
			tokens = append(tokens, Token{
				Type:     LITERAL,
				Value:    query[start:i],
				Position: start,
				TypeName: "LITERAL",
			})
			continue
		}

		// Operadores
		operatorFound := false
		for _, op := range sa.operators {
			if i+len(op) <= len(query) && query[i:i+len(op)] == op {
				tokens = append(tokens, Token{
					Type:     OPERATOR,
					Value:    op,
					Position: i,
					TypeName: "OPERATOR",
				})
				i += len(op)
				operatorFound = true
				break
			}
		}
		if operatorFound {
			continue
		}

		// Caracteres especiales
		if query[i] == ';' {
			tokens = append(tokens, Token{
				Type:     SEMICOLON,
				Value:    ";",
				Position: i,
				TypeName: "SEMICOLON",
			})
			i++
			continue
		}

		if query[i] == ',' {
			tokens = append(tokens, Token{
				Type:     COMMA,
				Value:    ",",
				Position: i,
				TypeName: "COMMA",
			})
			i++
			continue
		}

		if query[i] == '(' || query[i] == ')' {
			tokens = append(tokens, Token{
				Type:     PARENTHESIS,
				Value:    string(query[i]),
				Position: i,
				TypeName: "PARENTHESIS",
			})
			i++
			continue
		}

		// Identificadores y palabras clave
		if unicode.IsLetter(rune(query[i])) || query[i] == '_' {
			start := i
			for i < len(query) && (unicode.IsLetter(rune(query[i])) || unicode.IsDigit(rune(query[i])) || query[i] == '_') {
				i++
			}
			value := query[start:i]
			tokenType := IDENTIFIER
			typeName := "IDENTIFIER"
			
			if sa.keywords[strings.ToUpper(value)] {
				tokenType = KEYWORD
				typeName = "KEYWORD"
			}

			tokens = append(tokens, Token{
				Type:     tokenType,
				Value:    value,
				Position: start,
				TypeName: typeName,
			})
			continue
		}

		// Token desconocido
		tokens = append(tokens, Token{
			Type:     UNKNOWN,
			Value:    string(query[i]),
			Position: i,
			TypeName: "UNKNOWN",
		})
		i++
	}

	return tokens
}

// AnalyzeSyntax realiza el análisis sintáctico básico
func (sa *SQLAnalyzer) AnalyzeSyntax(tokens []Token) (bool, []string, string) {
	var errors []string
	var queryType string

	// Filtrar tokens de whitespace para análisis
	var filteredTokens []Token
	for _, token := range tokens {
		if token.Type != WHITESPACE {
			filteredTokens = append(filteredTokens, token)
		}
	}

	if len(filteredTokens) == 0 {
		return false, []string{"Query vacía"}, ""
	}

	// Determinar tipo de query
	firstToken := strings.ToUpper(filteredTokens[0].Value)
	switch firstToken {
	case "SELECT":
		queryType = "SELECT"
		errors = append(errors, sa.validateSelectQuery(filteredTokens)...)
	case "INSERT":
		queryType = "INSERT"
		errors = append(errors, sa.validateInsertQuery(filteredTokens)...)
	case "UPDATE":
		queryType = "UPDATE"
		errors = append(errors, sa.validateUpdateQuery(filteredTokens)...)
	case "DELETE":
		queryType = "DELETE"
		errors = append(errors, sa.validateDeleteQuery(filteredTokens)...)
	default:
		if filteredTokens[0].Type == KEYWORD {
			queryType = firstToken
		} else {
			errors = append(errors, "Query debe comenzar con una palabra clave SQL válida")
		}
	}

	return len(errors) == 0, errors, queryType
}

// validateSelectQuery valida la sintaxis de una query SELECT
func (sa *SQLAnalyzer) validateSelectQuery(tokens []Token) []string {
	var errors []string
	
	if len(tokens) < 3 {
		errors = append(errors, "SELECT query incompleta")
		return errors
	}

	// Buscar FROM
	fromFound := false
	for _, token := range tokens {
		if strings.ToUpper(token.Value) == "FROM" {
			fromFound = true
			break
		}
	}

	if !fromFound {
		errors = append(errors, "SELECT query debe incluir cláusula FROM")
	}

	return errors
}

// validateInsertQuery valida la sintaxis de una query INSERT
func (sa *SQLAnalyzer) validateInsertQuery(tokens []Token) []string {
	var errors []string
	
	if len(tokens) < 4 {
		errors = append(errors, "INSERT query incompleta")
		return errors
	}

	// Verificar estructura básica: INSERT INTO table
	if len(tokens) < 3 || strings.ToUpper(tokens[1].Value) != "INTO" {
		errors = append(errors, "INSERT debe incluir INTO")
	}

	return errors
}

// validateUpdateQuery valida la sintaxis de una query UPDATE
func (sa *SQLAnalyzer) validateUpdateQuery(tokens []Token) []string {
	var errors []string
	
	if len(tokens) < 4 {
		errors = append(errors, "UPDATE query incompleta")
		return errors
	}

	// Buscar SET
	setFound := false
	for _, token := range tokens {
		if strings.ToUpper(token.Value) == "SET" {
			setFound = true
			break
		}
	}

	if !setFound {
		errors = append(errors, "UPDATE query debe incluir cláusula SET")
	}

	return errors
}

// validateDeleteQuery valida la sintaxis de una query DELETE
func (sa *SQLAnalyzer) validateDeleteQuery(tokens []Token) []string {
	var errors []string
	
	if len(tokens) < 3 {
		errors = append(errors, "DELETE query incompleta")
		return errors
	}

	// Buscar FROM
	fromFound := false
	for _, token := range tokens {
		if strings.ToUpper(token.Value) == "FROM" {
			fromFound = true
			break
		}
	}

	if !fromFound {
		errors = append(errors, "DELETE query debe incluir cláusula FROM")
	}

	return errors
}

// DetectThreats realiza el análisis semántico para detectar amenazas
func (sa *SQLAnalyzer) DetectThreats(query string, tokens []Token) []ThreatDetection {
	var threats []ThreatDetection
	queryUpper := strings.ToUpper(query)

	// Detectar UNION injection
	if strings.Contains(queryUpper, "UNION") {
		unionRegex := regexp.MustCompile(`(?i)union\s+select`)
		if unionRegex.MatchString(query) {
			threats = append(threats, ThreatDetection{
				Type:        "UNION_INJECTION",
				Description: "Posible UNION injection detectada",
				Severity:    "HIGH",
				Position:    strings.Index(queryUpper, "UNION"),
			})
		}
	}

	// Detectar comentarios anómalos
	commentRegex := regexp.MustCompile(`--|\#|/\*|\*/`)
	if commentRegex.MatchString(query) {
		threats = append(threats, ThreatDetection{
			Type:        "SUSPICIOUS_COMMENT",
			Description: "Comentarios sospechosos que pueden indicar SQL injection",
			Severity:    "MEDIUM",
			Position:    commentRegex.FindStringIndex(query)[0],
		})
	}

	// Detectar concatenaciones peligrosas
	concatRegex := regexp.MustCompile(`(?i)(concat|char|ascii|\|\||\+\s*['"])`)
	if concatRegex.MatchString(query) {
		threats = append(threats, ThreatDetection{
			Type:        "DANGEROUS_CONCATENATION",
			Description: "Concatenación peligrosa detectada",
			Severity:    "HIGH",
			Position:    concatRegex.FindStringIndex(query)[0],
		})
	}

	// Detectar funciones de sistema peligrosas
	systemFuncs := []string{"LOAD_FILE", "INTO OUTFILE", "INTO DUMPFILE", "EXEC", "EXECUTE", "WAITFOR", "BENCHMARK", "SLEEP"}
	for _, fn := range systemFuncs {
		if strings.Contains(queryUpper, fn) {
			threats = append(threats, ThreatDetection{
				Type:        "SYSTEM_FUNCTION",
				Description: fmt.Sprintf("Función de sistema peligrosa detectada: %s", fn),
				Severity:    "CRITICAL",
				Position:    strings.Index(queryUpper, fn),
			})
		}
	}

	// Detectar múltiples statements
	if strings.Count(query, ";") > 1 {
		threats = append(threats, ThreatDetection{
			Type:        "MULTIPLE_STATEMENTS",
			Description: "Múltiples statements detectados, posible SQL injection",
			Severity:    "HIGH",
			Position:    strings.Index(query, ";"),
		})
	}

	// Detectar patrones de bypass de autenticación
	authBypassRegex := regexp.MustCompile(`(?i)(or\s+1\s*=\s*1|or\s+'1'\s*=\s*'1'|or\s+true|admin'\s*--|\'\s+or\s+\'\'\s*=\s*\'')`)
	if authBypassRegex.MatchString(query) {
		threats = append(threats, ThreatDetection{
			Type:        "AUTH_BYPASS",
			Description: "Patrón de bypass de autenticación detectado",
			Severity:    "CRITICAL",
			Position:    authBypassRegex.FindStringIndex(query)[0],
		})
	}

	return threats
}

// CalculateRiskLevel calcula el nivel de riesgo basado en las amenazas
func (sa *SQLAnalyzer) CalculateRiskLevel(threats []ThreatDetection) string {
	if len(threats) == 0 {
		return "LOW"
	}

	criticalCount := 0
	highCount := 0
	mediumCount := 0

	for _, threat := range threats {
		switch threat.Severity {
		case "CRITICAL":
			criticalCount++
		case "HIGH":
			highCount++
		case "MEDIUM":
			mediumCount++
		}
	}

	if criticalCount > 0 {
		return "CRITICAL"
	}
	if highCount > 0 {
		return "HIGH"
	}
	if mediumCount > 0 {
		return "MEDIUM"
	}

	return "LOW"
}

// AnalyzeQuery realiza el análisis completo de la query
func (sa *SQLAnalyzer) AnalyzeQuery(query string) AnalysisResult {
	// Análisis léxico
	tokens := sa.Tokenize(query)

	// Análisis sintáctico
	syntaxValid, syntaxErrors, queryType := sa.AnalyzeSyntax(tokens)

	// Análisis semántico - detección de amenazas
	threats := sa.DetectThreats(query, tokens)

	// Calcular nivel de riesgo
	riskLevel := sa.CalculateRiskLevel(threats)

	return AnalysisResult{
		Tokens:       tokens,
		IsMalicious:  len(threats) > 0,
		Threats:      threats,
		SyntaxValid:  syntaxValid,
		SyntaxErrors: syntaxErrors,
		QueryType:    queryType,
		RiskLevel:    riskLevel,
	}
}

// CORS middleware
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Handler para analizar queries SQL
func analyzeHandler(analyzer *SQLAnalyzer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Método no permitido", http.StatusMethodNotAllowed)
			return
		}

		var request struct {
			Query string `json:"query"`
		}

		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, "Error al decodificar JSON", http.StatusBadRequest)
			return
		}

		if request.Query == "" {
			http.Error(w, "Query no puede estar vacía", http.StatusBadRequest)
			return
		}

		result := analyzer.AnalyzeQuery(request.Query)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}
}

func main() {
	analyzer := NewSQLAnalyzer()

	mux := http.NewServeMux()
	mux.HandleFunc("/analyze", analyzeHandler(analyzer))
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	handler := corsMiddleware(mux)

	fmt.Println("Servidor iniciado en http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", handler))
}