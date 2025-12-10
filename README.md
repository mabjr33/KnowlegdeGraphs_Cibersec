# ***Knowledge Graph de Cibersegurança para Aplicações Web***

Projeto acadêmico desenvolvido para criar e manipular um grafo de conhecimento que representa vulnerabilidades em uma aplicação web fictícia chamada LojaVirtual.

O objetivo é demonstrar como Knowledge Graphs ajudam a organizar e analisar riscos de segurança de forma estruturada, conectando endpoints, parâmetros, tipos de vulnerabilidade, impactos e ataques.

## Estrutura do Projeto

O projeto implementa um grafo semântico usando apenas estruturas básicas de Python, sem bibliotecas de grafos prontas, respeitando os requisitos da disciplina.
Inclui:

• Criação de nós

• Criação de relacionamentos

• Consultas específicas

• Impressão formatada

• Exportação do grafo em formato DOT (Graphviz)

## Domínio: Cibersegurança Web

O grafo modela a aplicação LojaVirtual e seus principais pontos vulneráveis. Ele representa:

• Endpoints (login, produto, carrinho, checkout)

• Parâmetros enviados pelo usuário

• Tipos de vulnerabilidades (SQL Injection, XSS refletido, IDOR)

• Vulnerabilidades reais encontradas

• Impactos decorrentes

• Ferramentas utilizadas na descoberta

• Ataques completos que exploram vulnerabilidades

Esse modelo permite enxergar padrões, caminhos de ataque e impacto potencial de cada vulnerabilidade.

## Exemplo de Dados Representados

### Endpoints

• /login

• /produto

• /carrinho

• /checkout

### Vulnerabilidades

• SQLi no username do login

• SQLi na busca de produtos

• XSS refletido na busca

• IDOR no carrinho

### Impactos

• Exposição de dados

• Roubo de sessão

• Manipulação de pedidos

### Ferramentas

• Burp Suite

• Nmap

## Funcionalidades Implementadas
### 1. Criação do grafo

• Armazenamento de nós e relacionamentos

• Validação de existência

• Remoção e consulta

### 2. Consultas específicas de cibersegurança

• Vulnerabilidades por endpoint

• Vulnerabilidades por parâmetro

• Impactos associados a uma vulnerabilidade

• Tipo de cada vulnerabilidade

### 3. Impressão formatada

As informações aparecem organizadas em listas claras, indicando:

• Nome da vulnerabilidade

• Id interno

• Tipo

• Impacto

### 4. Exportação para Graphviz

O grafo pode ser visualizado em qualquer ferramenta Graphviz via arquivo:

```python
grafo_ciberseguranca.dot
```

## Como Executar
### 1. Rodar o script principal
```python
python grafo_conhecimento.py
```

### 2.Visualizar o grafo
Se quiser converter o arquivo .dot em imagem:
```python
dot -Tpng grafo_ciberseguranca.dot -o grafo_ciberseguranca.png
```
Ou abra o .dot em um visualizador online de Graphviz.

## Estrutura de Arquivos
```python
.
├── grafo_conhecimento.py
├── grafo_ciberseguranca.dot
└── README.md
```
