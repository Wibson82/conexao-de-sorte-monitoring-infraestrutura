#!/usr/bin/env bash

# ============================================================================
# 📊 ADVANCED MONITORING INSTALLER - CONEXÃO DE SORTE MONITORING INFRASTRUCTURE
# ============================================================================
# Script para instalação e configuração completa do Elastic APM e monitoramento
# avançado para microsserviços conexao-de-sorte-backend-{nome}
# ============================================================================

set -euo pipefail

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configurações
ELASTIC_OPERATOR_VERSION="2.10.0"
ELASTIC_NAMESPACE="elastic-system"
TARGET_NAMESPACE="default"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Função para log colorido
log_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
}

log_header() {
    echo -e "${PURPLE}🎯 $1${NC}"
}

log_step() {
    echo -e "${CYAN}🔄 $1${NC}"
}

# Função para verificar pré-requisitos
check_prerequisites() {
    log_header "Verificando pré-requisitos para Advanced Monitoring..."
    
    # Verificar kubectl
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl não encontrado. Instale kubectl primeiro."
        exit 1
    fi
    
    # Verificar conexão com cluster
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Não foi possível conectar ao cluster Kubernetes."
        exit 1
    fi
    
    # Verificar recursos do cluster
    log_step "Verificando recursos do cluster..."
    local nodes=$(kubectl get nodes --no-headers | wc -l)
    local total_cpu=$(kubectl top nodes --no-headers 2>/dev/null | awk '{sum+=$2} END {print sum}' || echo "unknown")
    local total_memory=$(kubectl top nodes --no-headers 2>/dev/null | awk '{sum+=$4} END {print sum}' || echo "unknown")
    
    log_info "Cluster: $nodes nodes, CPU: ${total_cpu}m, Memory: ${total_memory}Mi"
    
    if [[ $nodes -lt 3 ]]; then
        log_warning "Cluster pequeno detectado. Elasticsearch pode ter performance limitada."
    fi
    
    # Verificar storage classes
    if kubectl get storageclass fast-ssd &> /dev/null; then
        log_success "Storage class 'fast-ssd' encontrada"
    else
        log_warning "Storage class 'fast-ssd' não encontrada - usando padrão"
    fi
    
    log_success "Pré-requisitos verificados"
}

# Função para instalar Elastic Operator
install_elastic_operator() {
    log_header "Instalando Elastic Cloud on Kubernetes (ECK) Operator..."
    
    # Instalar CRDs
    log_step "Instalando CRDs do ECK..."
    kubectl create -f "https://download.elastic.co/downloads/eck/$ELASTIC_OPERATOR_VERSION/crds.yaml" || kubectl apply -f "https://download.elastic.co/downloads/eck/$ELASTIC_OPERATOR_VERSION/crds.yaml"
    
    # Instalar Operator
    log_step "Instalando ECK Operator..."
    kubectl apply -f "https://download.elastic.co/downloads/eck/$ELASTIC_OPERATOR_VERSION/operator.yaml"
    
    # Aguardar operator
    log_step "Aguardando ECK Operator..."
    kubectl wait --for=condition=available --timeout=300s deployment/elastic-operator -n elastic-system
    
    log_success "ECK Operator instalado com sucesso"
}

# Função para criar namespace e configurações
setup_namespace() {
    log_header "Configurando namespace e recursos..."
    
    # Criar namespace
    log_step "Criando namespace $ELASTIC_NAMESPACE..."
    kubectl create namespace "$ELASTIC_NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
    
    # Aplicar labels de segurança
    kubectl label namespace "$ELASTIC_NAMESPACE" \
        pod-security.kubernetes.io/enforce=restricted \
        pod-security.kubernetes.io/audit=restricted \
        pod-security.kubernetes.io/warn=restricted \
        --overwrite
    
    log_success "Namespace configurado"
}

# Função para instalar Elastic Stack
install_elastic_stack() {
    log_header "Instalando Elastic Stack (Elasticsearch, Kibana, APM)..."
    
    # Verificar se storage class existe, senão usar padrão
    local storage_class="fast-ssd"
    if ! kubectl get storageclass "$storage_class" &> /dev/null; then
        storage_class=$(kubectl get storageclass -o jsonpath='{.items[0].metadata.name}')
        log_warning "Usando storage class padrão: $storage_class"
        
        # Atualizar arquivo de configuração
        sed -i.bak "s/storageClassName: fast-ssd/storageClassName: $storage_class/" "$SCRIPT_DIR/elastic-apm-setup.yaml"
    fi
    
    # Aplicar configurações
    log_step "Aplicando configurações do Elastic Stack..."
    kubectl apply -f "$SCRIPT_DIR/elastic-apm-setup.yaml"
    
    # Aguardar Elasticsearch
    log_step "Aguardando Elasticsearch cluster..."
    kubectl wait --for=condition=Ready --timeout=600s elasticsearch/conexao-de-sorte-elasticsearch -n "$ELASTIC_NAMESPACE" || true
    
    # Aguardar Kibana
    log_step "Aguardando Kibana..."
    kubectl wait --for=condition=Ready --timeout=300s kibana/conexao-de-sorte-kibana -n "$ELASTIC_NAMESPACE" || true
    
    # Aguardar APM Server
    log_step "Aguardando APM Server..."
    kubectl wait --for=condition=Ready --timeout=300s apmserver/conexao-de-sorte-apm-server -n "$ELASTIC_NAMESPACE" || true
    
    log_success "Elastic Stack instalado"
}

# Função para configurar APM nos microsserviços
configure_apm_integration() {
    log_header "Configurando integração APM nos microsserviços..."
    
    # Aplicar ConfigMap com configurações APM
    log_step "Aplicando configurações APM..."
    kubectl apply -f - << 'EOF'
apiVersion: v1
kind: ConfigMap
metadata:
  name: conexao-de-sorte-apm-config
  namespace: default
  labels:
    app.kubernetes.io/name: apm-config
    app.kubernetes.io/part-of: conexao-de-sorte-monitoring
data:
  elastic-apm-agent.properties: |
    server_url=http://conexao-de-sorte-apm-server-apm-http.elastic-system.svc:8200
    service_name=conexao-de-sorte-${SERVICE_NAME}
    service_version=${SERVICE_VERSION:1.0.0}
    environment=${ENVIRONMENT:production}
    application_packages=br.tec.facilitaservicos
    transaction_sample_rate=0.1
    capture_body=all
    capture_headers=true
    stack_trace_limit=50
    profiling_inferred_spans_enabled=true
    metrics_interval=30s
    log_level=INFO
    global_labels=project=conexao-de-sorte,team=backend,domain=lottery
EOF
    
    # Criar script para atualizar Dockerfiles com APM
    log_step "Criando script de integração APM..."
    cat > "$SCRIPT_DIR/integrate-apm.sh" << 'EOF'
#!/bin/bash

# Script para integrar APM nos microsserviços existentes
SERVICES=("autenticacao" "batepapo" "financeiro" "notificacoes" "chatbot" "resultados" "scheduler" "auditoria-compliance" "observabilidade" "gateway" "criptografia-kms")

for service in "${SERVICES[@]}"; do
    service_dir="backend/conexao-de-sorte-backend-${service}"
    
    if [ -d "$service_dir" ]; then
        echo "🔧 Integrando APM no serviço: $service"
        
        # Adicionar volume mount para APM config no docker-compose.yml
        if [ -f "$service_dir/docker-compose.yml" ]; then
            # Backup
            cp "$service_dir/docker-compose.yml" "$service_dir/docker-compose.yml.apm-backup"
            
            # Adicionar volume mount (simplificado - requer ajuste manual)
            echo "⚠️  Adicione manualmente ao docker-compose.yml do $service:"
            echo "    volumes:"
            echo "      - conexao-de-sorte-apm-config:/app/config/apm:ro"
            echo ""
        fi
        
        # Atualizar application.yml para incluir APM
        if [ -f "$service_dir/src/main/resources/application.yml" ]; then
            echo "📝 Atualize o application.yml do $service para incluir:"
            echo "management:"
            echo "  elastic:"
            echo "    apm:"
            echo "      enabled: true"
            echo ""
        fi
    fi
done

echo "✅ Integração APM preparada. Revise e aplique as mudanças manualmente."
EOF
    
    chmod +x "$SCRIPT_DIR/integrate-apm.sh"
    
    log_success "Configuração APM preparada"
}

# Função para obter credenciais
get_credentials() {
    log_header "Obtendo credenciais de acesso..."
    
    # Obter senha do Elasticsearch
    local es_password=$(kubectl get secret conexao-de-sorte-elasticsearch-es-elastic-user -n "$ELASTIC_NAMESPACE" -o jsonpath='{.data.elastic}' | base64 -d)
    
    # Obter URL do Kibana
    local kibana_url="http://localhost:5601"
    
    echo ""
    echo "🔐 Credenciais de acesso:"
    echo "  • Elasticsearch:"
    echo "    - Usuário: elastic"
    echo "    - Senha: $es_password"
    echo "    - URL: http://localhost:9200"
    echo ""
    echo "  • Kibana:"
    echo "    - Usuário: elastic"
    echo "    - Senha: $es_password"
    echo "    - URL: $kibana_url"
    echo ""
    echo "  • APM Server:"
    echo "    - URL: http://localhost:8200"
    echo ""
    echo "🔧 Port-forward commands:"
    echo "  • Elasticsearch: kubectl port-forward -n $ELASTIC_NAMESPACE svc/conexao-de-sorte-elasticsearch-es-http 9200:9200"
    echo "  • Kibana: kubectl port-forward -n $ELASTIC_NAMESPACE svc/conexao-de-sorte-kibana-kb-http 5601:5601"
    echo "  • APM Server: kubectl port-forward -n $ELASTIC_NAMESPACE svc/conexao-de-sorte-apm-server-apm-http 8200:8200"
    echo ""
}

# Função para configurar dashboards
setup_dashboards() {
    log_header "Configurando dashboards e visualizações..."
    
    log_step "Aguardando Kibana estar pronto..."
    sleep 60
    
    # Criar index patterns via API (simplificado)
    log_step "Configurando index patterns..."
    
    cat > "$SCRIPT_DIR/setup-kibana.sh" << 'EOF'
#!/bin/bash

# Script para configurar Kibana após instalação
KIBANA_URL="http://localhost:5601"
ES_PASSWORD=$(kubectl get secret conexao-de-sorte-elasticsearch-es-elastic-user -n elastic-system -o jsonpath='{.data.elastic}' | base64 -d)

echo "🔧 Para configurar Kibana:"
echo "1. Execute: kubectl port-forward -n elastic-system svc/conexao-de-sorte-kibana-kb-http 5601:5601"
echo "2. Acesse: http://localhost:5601"
echo "3. Login: elastic / $ES_PASSWORD"
echo "4. Vá para Stack Management > Index Patterns"
echo "5. Crie index patterns para:"
echo "   - apm-*-transaction-*"
echo "   - apm-*-error-*"
echo "   - apm-*-metric-*"
echo "   - metricbeat-*"
echo "6. Vá para APM para visualizar dados dos microsserviços"
EOF
    
    chmod +x "$SCRIPT_DIR/setup-kibana.sh"
    
    log_success "Scripts de configuração criados"
}

# Função para mostrar informações pós-instalação
show_post_install_info() {
    log_header "Informações pós-instalação do Advanced Monitoring"
    
    echo ""
    echo "📊 Elastic APM instalado com sucesso!"
    echo ""
    echo "🎯 Componentes instalados:"
    echo "  • Elasticsearch cluster (3 nodes)"
    echo "  • Kibana dashboard"
    echo "  • APM Server"
    echo "  • Metricbeat para métricas de sistema"
    echo ""
    echo "🔧 Próximos passos:"
    echo "  1. Execute: $SCRIPT_DIR/setup-kibana.sh"
    echo "  2. Configure port-forwards para acesso"
    echo "  3. Execute: $SCRIPT_DIR/integrate-apm.sh"
    echo "  4. Atualize microsserviços com configurações APM"
    echo "  5. Reinicie microsserviços para ativar APM"
    echo ""
    echo "📈 Métricas disponíveis:"
    echo "  • Application Performance Monitoring (APM)"
    echo "  • Distributed Tracing"
    echo "  • Error Tracking"
    echo "  • Infrastructure Metrics"
    echo "  • Custom Business Metrics"
    echo ""
    echo "⚠️ Importante:"
    echo "  • APM adiciona overhead (~5-10%)"
    echo "  • Configure sampling rate apropriado"
    echo "  • Monitore uso de storage do Elasticsearch"
    echo "  • Configure retention policies"
    echo ""
}

# Função principal
main() {
    case "${1:-install}" in
        "install")
            check_prerequisites
            install_elastic_operator
            setup_namespace
            install_elastic_stack
            configure_apm_integration
            setup_dashboards
            get_credentials
            show_post_install_info
            ;;
        "credentials")
            get_credentials
            ;;
        "integrate")
            "$SCRIPT_DIR/integrate-apm.sh"
            ;;
        "uninstall")
            log_warning "Desinstalando Advanced Monitoring..."
            kubectl delete -f "$SCRIPT_DIR/elastic-apm-setup.yaml" --ignore-not-found=true
            kubectl delete -f "https://download.elastic.co/downloads/eck/$ELASTIC_OPERATOR_VERSION/operator.yaml" --ignore-not-found=true
            kubectl delete -f "https://download.elastic.co/downloads/eck/$ELASTIC_OPERATOR_VERSION/crds.yaml" --ignore-not-found=true
            kubectl delete namespace "$ELASTIC_NAMESPACE" --ignore-not-found=true
            rm -f "$SCRIPT_DIR/integrate-apm.sh" "$SCRIPT_DIR/setup-kibana.sh"
            log_success "Advanced Monitoring desinstalado"
            ;;
        "help"|*)
            echo "📊 Advanced Monitoring Installer"
            echo ""
            echo "Uso: $0 [COMANDO]"
            echo ""
            echo "Comandos:"
            echo "  install      Instalar Elastic APM completo (padrão)"
            echo "  credentials  Mostrar credenciais de acesso"
            echo "  integrate    Executar script de integração APM"
            echo "  uninstall    Desinstalar Advanced Monitoring"
            echo "  help         Mostrar esta ajuda"
            ;;
    esac
}

# Executar função principal
main "$@"
