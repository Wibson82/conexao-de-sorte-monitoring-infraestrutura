# 📈 conexao-de-sorte-monitoring-infraestrutura

## 📋 Descrição

Advanced Monitoring Infrastructure com Elastic APM e Distributed Tracing para a plataforma Conexão de Sorte.

## 🎯 Funcionalidades

### Principais Recursos
- Configuração automatizada via scripts
- Integração com Kubernetes
- Monitoramento e observabilidade
- Alta disponibilidade e resiliência
- Otimizado para Hostinger KVM 2

### Componentes Inclusos
- Arquivos de configuração YAML
- Scripts de instalação automatizada
- Documentação completa
- Exemplos de uso

## 🚀 Instalação

### Pré-requisitos
- Kubernetes cluster ativo
- kubectl configurado
- Acesso administrativo ao cluster

### Instalação Rápida
```bash
# Executar script de instalação
bash install-*.sh

# Ou aplicar configurações manualmente
kubectl apply -f *.yaml
```

## 🔧 Configuração

### Variáveis de Ambiente
Consulte os arquivos de configuração para variáveis específicas.

### Personalização
Edite os arquivos YAML conforme necessário para seu ambiente.

## 📊 Monitoramento

### Métricas Disponíveis
- Status dos componentes
- Performance metrics
- Health checks
- Alertas automáticos

### Dashboards
Integração com Grafana e Prometheus para visualização.

## 🛠️ Troubleshooting

### Problemas Comuns
1. **Falha na instalação**: Verificar pré-requisitos
2. **Recursos insuficientes**: Ajustar limits no YAML
3. **Conectividade**: Verificar network policies

### Logs
```bash
# Ver logs dos pods
kubectl logs -l app.kubernetes.io/part-of=conexao-de-sorte-Advanced Monitoring

# Ver eventos
kubectl get events --sort-by=.metadata.creationTimestamp
```

## 📚 Documentação

### Arquivos Importantes
- `README.md` - Esta documentação
- `*.yaml` - Configurações Kubernetes
- `install-*.sh` - Scripts de instalação

### Links Úteis
- [Documentação Kubernetes](https://kubernetes.io/docs/)
- [Conexão de Sorte - Arquitetura](../docs/)

## 🤝 Contribuição

### Como Contribuir
1. Fork o repositório
2. Crie uma branch para sua feature
3. Commit suas mudanças
4. Abra um Pull Request

### Padrões
- Seguir nomenclatura: `conexao-de-sorte-{nome}-infraestrutura`
- Documentar todas as mudanças
- Testar em ambiente de desenvolvimento

## 📄 Licença

Este projeto faz parte da plataforma Conexão de Sorte.

## 📞 Suporte

Para suporte técnico, consulte a documentação principal ou abra uma issue.

---

*Última atualização: 25/09/2025*  
*Parte da infraestrutura Conexão de Sorte*
