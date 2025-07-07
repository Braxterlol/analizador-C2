import React, { useState } from 'react';
import { AlertCircle, Shield, Code, CheckCircle, XCircle, AlertTriangle, Search, FileText, Bug, Zap } from 'lucide-react';
import './App.css';

const SQLAnalyzer = () => {
  const [query, setQuery] = useState('');
  const [analysis, setAnalysis] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const exampleQueries = [
    {
      name: "Query Normal",
      query: "SELECT * FROM users WHERE id = 1"
    },
    {
      name: "UNION Injection",
      query: "SELECT * FROM users WHERE id = 1 UNION SELECT username, password FROM admin --"
    },
    {
      name: "Bypass de Autenticación",
      query: "SELECT * FROM users WHERE username = 'admin' OR '1'='1' --"
    },
    {
      name: "Concatenación Peligrosa",
      query: "SELECT * FROM users WHERE name = CONCAT('test', CHAR(39))"
    }
  ];

  const analyzeQuery = async () => {
    if (!query.trim()) {
      setError('Por favor ingresa una consulta SQL');
      return;
    }

    setLoading(true);
    setError('');

    try {
      const response = await fetch('http://localhost:8080/analyze', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ query }),
      });

      if (!response.ok) {
        throw new Error('Error al analizar la consulta');
      }

      const data = await response.json();
      setAnalysis(data);
    } catch (err) {
      setError('Error al conectar con el servidor. Asegúrate de que el backend esté ejecutándose en http://localhost:8080');
    } finally {
      setLoading(false);
    }
  };

  const loadExample = (exampleQuery) => {
    setQuery(exampleQuery);
    setAnalysis(null);
    setError('');
  };

  const getThreatIcon = (type) => {
    const icons = {
      UNION_INJECTION: <Zap className="threat-icon" />,
      SUSPICIOUS_COMMENT: <AlertTriangle className="threat-icon" />,
      DANGEROUS_CONCATENATION: <Bug className="threat-icon" />,
      SYSTEM_FUNCTION: <AlertCircle className="threat-icon" />,
      MULTIPLE_STATEMENTS: <FileText className="threat-icon" />,
      AUTH_BYPASS: <Shield className="threat-icon" />
    };
    return icons[type] || <AlertCircle className="threat-icon" />;
  };

  const getRiskLevelClass = (riskLevel) => {
    const classes = {
      LOW: 'risk-low',
      MEDIUM: 'risk-medium',
      HIGH: 'risk-high',
      CRITICAL: 'risk-critical'
    };
    return classes[riskLevel] || 'risk-low';
  };

  const getSeverityClass = (severity) => {
    const classes = {
      LOW: 'severity-low',
      MEDIUM: 'severity-medium',
      HIGH: 'severity-high',
      CRITICAL: 'severity-critical'
    };
    return classes[severity] || 'severity-low';
  };

  const getTokenTypeClass = (tokenType) => {
    const classes = {
      KEYWORD: 'token-keyword',
      OPERATOR: 'token-operator',
      LITERAL: 'token-literal',
      IDENTIFIER: 'token-identifier',
      COMMENT: 'token-comment',
      SEMICOLON: 'token-punctuation',
      COMMA: 'token-punctuation',
      PARENTHESIS: 'token-punctuation',
      UNKNOWN: 'token-unknown'
    };
    return classes[tokenType] || 'token-unknown';
  };

  return (
    <div className="app-container">
      <div className="main-wrapper">
        {/* Header */}
        <div className="header">
          <div className="header-title-container">
            <Shield className="header-icon" />
            <h1 className="header-title">Analizador de Consultas SQL</h1>
          </div>
          <p className="header-subtitle">
            Detecta inyecciones SQL y patrones maliciosos en consultas de base de datos
          </p>
        </div>

        <div className="main-grid">
          {/* Panel de Input */}
          <div className="main-content">
            <div className="card">
              <div className="card-header">
                <Code className="card-icon" />
                <h2 className="card-title">Consulta SQL</h2>
              </div>
              
              <textarea
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Ingresa tu consulta SQL aquí..."
                className="query-textarea"
              />
              
              <div className="control-bar">
                <button
                  onClick={analyzeQuery}
                  disabled={loading}
                  className="btn-primary"
                >
                  <Search className="btn-icon" />
                  {loading ? 'Analizando...' : 'Analizar Consulta'}
                </button>
                
                <div className="char-counter">
                  {query.length} caracteres
                </div>
              </div>

              {error && (
                <div className="error-message">
                  <div className="error-content">
                    <XCircle className="error-icon" />
                    <span className="error-text">{error}</span>
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Panel de Ejemplos */}
          <div className="card">
            <h3 className="examples-title">Consultas de Ejemplo</h3>
            <div className="examples-list">
              {exampleQueries.map((example, index) => (
                <button
                  key={index}
                  onClick={() => loadExample(example.query)}
                  className="example-button"
                >
                  <div className="example-name">{example.name}</div>
                  <div className="example-query">
                    {example.query}
                  </div>
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Resultados del Análisis */}
        {analysis && (
          <div className="results-container">
            {/* Resumen del Análisis */}
            <div className="card">
              <h3 className="card-title">Resumen del Análisis</h3>
              <div className="summary-grid">
                <div className="summary-item">
                  <div className="summary-item-header">
                    <span className="summary-label">Tipo de Consulta</span>
                    <Code className="summary-icon" />
                  </div>
                  <div className="summary-value">
                    {analysis?.queryType || 'Desconocido'}
                  </div>
                </div>

                <div className="summary-item">
                  <div className="summary-item-header">
                    <span className="summary-label">Sintaxis</span>
                    {analysis.syntaxValid ? 
                      <CheckCircle className="summary-icon" style={{color: '#059669'}} /> : 
                      <XCircle className="summary-icon" style={{color: '#dc2626'}} />
                    }
                  </div>
                  <div className="summary-value">
                    {analysis?.syntaxValid ? 'Válida' : 'Inválida'}
                  </div>
                </div>

                <div className="summary-item">
                  <div className="summary-item-header">
                    <span className="summary-label">Amenazas</span>
                    <AlertTriangle className="summary-icon" style={{color: '#ea580c'}} />
                  </div>
                  <div className="summary-value">
                    {analysis?.threats?.length || 0}
                  </div>
                </div>

                <div className="summary-item">
                  <div className="summary-item-header">
                    <span className="summary-label">Nivel de Riesgo</span>
                    <Shield className="summary-icon" />
                  </div>
                  <div className={`summary-value ${getRiskLevelClass(analysis?.riskLevel)}`}>
                    {analysis?.riskLevel}
                  </div>
                </div>
              </div>
            </div>

            {/* Errores de Sintaxis */}
            {!analysis?.syntaxValid && analysis?.syntaxErrors?.length > 0 && (
              <div className="card">
                <div className="card-header">
                  <XCircle className="card-icon" style={{color: '#dc2626'}} />
                  <h3 className="card-title">Errores de Sintaxis</h3>
                </div>
                <div className="syntax-errors">
                  {analysis.syntaxErrors.map((error, index) => (
                    <div key={index} className="syntax-error-item">
                      <span>{error}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Amenazas Detectadas */}
            {analysis?.threats?.length > 0 && (
              <div className="card">
                <div className="card-header">
                  <AlertCircle className="card-icon" style={{color: '#dc2626'}} />
                  <h3 className="card-title">Amenazas Detectadas</h3>
                </div>
                <div className="threats-list">
                  {analysis.threats.map((threat, index) => (
                    <div key={index} className="threat-item">
                      <div className="threat-header">
                        <div className="threat-title-container">
                          {getThreatIcon(threat.type)}
                          <span className="threat-title">
                            {threat.type.replace(/_/g, ' ')}
                          </span>
                        </div>
                        <span className={`threat-severity ${getSeverityClass(threat.severity)}`}>
                          {threat.severity}
                        </span>
                      </div>
                      <p className="threat-description">{threat.description}</p>
                      <p className="threat-position">
                        Posición: {threat.position}
                      </p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Análisis Léxico - Tokens */}
            <div className="card">
              <div className="card-header">
                <FileText className="card-icon" />
                <h3 className="card-title">Análisis Léxico</h3>
              </div>
              
              {/* Estadísticas de Tokens */}
              <div>
                <h4 className="token-table-title">Estadísticas de Tokens</h4>
                <div className="token-stats-grid">
                  {Object.entries(
                    (analysis?.tokens || []).reduce((acc, token) => {
                      if (token.typeName !== 'WHITESPACE') {
                        acc[token.typeName] = (acc[token.typeName] || 0) + 1;
                      }
                      return acc;
                    }, {})
                  ).map(([type, count]) => (
                    <div key={type} className="token-stat-item">
                      <div className="token-stat-count">{count}</div>
                      <div className="token-stat-label">{type}</div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Tokens Visuales */}
              <div>
                <h4 className="token-table-title">Tokens Identificados</h4>
                <div className="tokens-visual">
                  {(analysis?.tokens || [])
                    .filter(token => token.typeName !== 'WHITESPACE')
                    .map((token, index) => (
                      <span
                        key={index}
                        className={`token-chip ${getTokenTypeClass(token.typeName)}`}
                        title={`Tipo: ${token.typeName}, Posición: ${token.position}`}
                      >
                        {token.value}
                      </span>
                    ))}
                </div>
              </div>

              {/* Tabla Detallada de Tokens */}
              <div className="token-table-container">
                <h4 className="token-table-title">Detalles de Tokens</h4>
                <table className="token-table">
                  <thead>
                    <tr>
                      <th>#</th>
                      <th>Token</th>
                      <th>Tipo</th>
                      <th>Posición</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(analysis?.tokens || [])
                      .filter(token => token.typeName !== 'WHITESPACE')
                      .map((token, index) => (
                        <tr key={index}>
                          <td className="token-index">{index + 1}</td>
                          <td className="token-value">{token.value}</td>
                          <td>
                            <span className={`token-chip ${getTokenTypeClass(token.typeName)}`}>
                              {token.typeName}
                            </span>
                          </td>
                          <td className="token-position">{token.position}</td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Análisis de Seguridad */}
            <div className="card">
              <div className="card-header">
                <Shield className="card-icon" style={{color: '#059669'}} />
                <h3 className="card-title">Análisis de Seguridad</h3>
              </div>
              
              <div className="security-grid">
                <div>
                  <h4 className="security-section-title">Estado de Seguridad</h4>
                  <div className="security-status-list">
                    <div className="security-status-item">
                      <span className="security-status-label">Consulta Maliciosa</span>
                      <div className="security-status-value">
                        {analysis?.isMalicious ? (
                          <>
                            <XCircle className="security-status-icon" style={{color: '#dc2626'}} />
                            <span className="security-status-text security-status-negative">Sí</span>
                          </>
                        ) : (
                          <>
                            <CheckCircle className="security-status-icon" style={{color: '#059669'}} />
                            <span className="security-status-text security-status-positive">No</span>
                          </>
                        )}
                      </div>
                    </div>
                    
                    <div className="security-status-item">
                      <span className="security-status-label">Sintaxis Válida</span>
                      <div className="security-status-value">
                        {analysis?.syntaxValid ? (
                          <>
                            <CheckCircle className="security-status-icon" style={{color: '#059669'}} />
                            <span className="security-status-text security-status-positive">Sí</span>
                          </>
                        ) : (
                          <>
                            <XCircle className="security-status-icon" style={{color: '#dc2626'}} />
                            <span className="security-status-text security-status-negative">No</span>
                          </>
                        )}
                      </div>
                    </div>
                  </div>
                </div>

                <div>
                  <h4 className="security-section-title">Recomendaciones</h4>
                  <div className="recommendations-list">
                    {analysis?.isMalicious ? (
                      <div className="recommendation-item recommendation-malicious">
                        <p className="recommendation-text">
                          ⚠️ Esta consulta contiene patrones maliciosos. No debe ejecutarse en un entorno de producción.
                        </p>
                      </div>
                    ) : (
                      <div className="recommendation-item recommendation-safe">
                        <p className="recommendation-text">
                          ✅ Esta consulta parece segura desde la perspectiva de inyección SQL.
                        </p>
                      </div>
                    )}
                    
                    {!analysis?.syntaxValid && (
                      <div className="recommendation-item recommendation-syntax">
                        <p className="recommendation-text">
                          💡 Revisa los errores de sintaxis antes de ejecutar la consulta.
                        </p>
                      </div>
                    )}
                    
                    <div className="recommendation-item recommendation-general">
                      <p className="recommendation-text">
                        💡 Siempre usa consultas parametrizadas y valida las entradas del usuario.
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default SQLAnalyzer;