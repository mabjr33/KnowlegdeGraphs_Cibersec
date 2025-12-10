from typing import Dict, List, Any


class No:
    def __init__(self, identificador: str, tipo: str, rotulo: str, propriedades: Dict[str, Any] | None = None):
        self.id = identificador
        self.tipo = tipo
        self.rotulo = rotulo
        self.propriedades = propriedades or {}

    def __repr__(self) -> str:
        return f"No(id={self.id}, tipo={self.tipo}, rotulo={self.rotulo})"


class Relacao:
    def __init__(self, origem: str, destino: str, tipo: str):
        self.origem = origem
        self.destino = destino
        self.tipo = tipo

    def __repr__(self) -> str:
        return f"Relacao({self.origem} --{self.tipo}--> {self.destino})"


class GrafoConhecimento:
    def __init__(self):
        self.nos: Dict[str, No] = {}
        self.relacoes: List[Relacao] = []

    # Operacoes basicas

    def adicionar_no(self, no: No) -> None:
        if no.id in self.nos:
            raise ValueError(f"No com id {no.id} ja existe")
        self.nos[no.id] = no

    def remover_no(self, identificador: str) -> None:
        if identificador not in self.nos:
            return
        self.relacoes = [
            r for r in self.relacoes
            if r.origem != identificador and r.destino != identificador
        ]
        del self.nos[identificador]

    def adicionar_relacao(self, origem: str, destino: str, tipo: str) -> None:
        if origem not in self.nos or destino not in self.nos:
            raise ValueError("Origem ou destino inexistentes")
        relacao = Relacao(origem, destino, tipo)
        self.relacoes.append(relacao)

    def remover_relacao(self, origem: str, destino: str, tipo: str | None = None) -> None:
        nova_lista = []
        for r in self.relacoes:
            if r.origem == origem and r.destino == destino:
                if tipo is None or r.tipo == tipo:
                    continue
            nova_lista.append(r)
        self.relacoes = nova_lista

    # Consultas

    def obter_no(self, identificador: str) -> No | None:
        return self.nos.get(identificador)

    def buscar_nos_por_tipo(self, tipo: str) -> List[No]:
        return [n for n in self.nos.values() if n.tipo == tipo]

    def buscar_nos_por_propriedade(self, chave: str, valor: Any) -> List[No]:
        return [
            n for n in self.nos.values()
            if n.propriedades.get(chave) == valor
        ]

    def vizinhos(self, identificador: str, tipo_relacao: str | None = None) -> List[No]:
        resultado = []
        for r in self.relacoes:
            if r.origem == identificador:
                if tipo_relacao is None or r.tipo == tipo_relacao:
                    destino = self.nos.get(r.destino)
                    if destino:
                        resultado.append(destino)
        return resultado

    # Consultas especificas para o tema de ciberseguranca

    def vulnerabilidades_por_endpoint(self, endpoint_id: str) -> List[No]:
        vulnerabilidades = []
        for r in self.relacoes:
            if r.destino == endpoint_id and r.tipo == "ESTA_NO_ENDPOINT":
                vul = self.nos.get(r.origem)
                if vul:
                    vulnerabilidades.append(vul)
        return vulnerabilidades

    def vulnerabilidades_por_parametro(self, parametro_id: str) -> List[No]:
        vulnerabilidades = []
        for r in self.relacoes:
            if r.destino == parametro_id and r.tipo == "AFETA_PARAMETRO":
                vul = self.nos.get(r.origem)
                if vul:
                    vulnerabilidades.append(vul)
        return vulnerabilidades

    def impactos_de_vulnerabilidade(self, vulnerabilidade_id: str) -> List[No]:
        impactos = []
        for r in self.relacoes:
            if r.origem == vulnerabilidade_id and r.tipo == "GERA_IMPACTO":
                imp = self.nos.get(r.destino)
                if imp:
                    impactos.append(imp)
        return impactos
    
    def tipos_de_vulnerabilidade(self, vulnerabilidade_id: str) -> list[No]:
        tipos = []
        for r in self.relacoes:
            if r.origem == vulnerabilidade_id and r.tipo == "E_DO_TIPO":
                tipo_no = self.nos.get(r.destino)
                if tipo_no:
                    tipos.append(tipo_no)
        return tipos
    
    def exportar_para_dot(self, caminho_arquivo: str) -> None:
        """Gera um arquivo DOT para visualizacao do grafo."""
        with open(caminho_arquivo, "w", encoding="utf8") as f:
            f.write("digraph GrafoConhecimento {\n")
            f.write("  rankdir=LR;\n")  # opcional, deixa o grafo na horizontal

            # Nos
            for no in self.nos.values():
                label = f"{no.rotulo}\n({no.tipo})"
                f.write(f'  "{no.id}" [label="{label}"];\n')

            # Relacoes
            for r in self.relacoes:
                f.write(f'  "{r.origem}" -> "{r.destino}" [label="{r.tipo}"];\n')

            f.write("}\n")




def criar_grafo_exemplo() -> GrafoConhecimento:
    g = GrafoConhecimento()

    # Aplicacao
    g.adicionar_no(No("app_loja", "Aplicacao", "LojaVirtual"))

    # Endpoints
    g.adicionar_no(No("ep_login", "Endpoint", "Login", {"caminho": "/login"}))
    g.adicionar_no(No("ep_produto", "Endpoint", "Produto", {"caminho": "/produto"}))
    g.adicionar_no(No("ep_carrinho", "Endpoint", "Carrinho", {"caminho": "/carrinho"}))
    g.adicionar_no(No("ep_checkout", "Endpoint", "Checkout", {"caminho": "/checkout"}))

    # Parametros
    g.adicionar_no(No("param_username", "Parametro", "username"))
    g.adicionar_no(No("param_password", "Parametro", "password"))
    g.adicionar_no(No("param_busca", "Parametro", "busca"))
    g.adicionar_no(No("param_id_produto", "Parametro", "id_produto"))
    g.adicionar_no(No("param_quantidade", "Parametro", "quantidade"))

    # Tipos de vulnerabilidade
    g.adicionar_no(No("tv_sqli", "TipoVulnerabilidade", "SQL Injection"))
    g.adicionar_no(No("tv_xss_refletido", "TipoVulnerabilidade", "XSS refletido"))
    g.adicionar_no(No("tv_idor", "TipoVulnerabilidade", "IDOR"))

    # Vulnerabilidades
    g.adicionar_no(No("vul_sqli_login_username", "Vulnerabilidade", "SQLi no username de login"))
    g.adicionar_no(No("vul_sqli_busca_produto", "Vulnerabilidade", "SQLi no parametro de busca"))
    g.adicionar_no(No("vul_xss_busca_produto", "Vulnerabilidade", "XSS refletido na busca"))
    g.adicionar_no(No("vul_idor_carrinho_id_produto", "Vulnerabilidade", "IDOR no carrinho"))

    # Impactos
    g.adicionar_no(No("imp_exposicao_clientes", "Impacto", "Exposicao de dados de clientes"))
    g.adicionar_no(No("imp_roubo_sessao", "Impacto", "Roubo de sessao"))
    g.adicionar_no(No("imp_manipulacao_pedidos", "Impacto", "Manipulacao de pedidos"))

    # Ferramentas
    g.adicionar_no(No("tool_burp", "Ferramenta", "Burp Suite"))
    g.adicionar_no(No("tool_nmap", "Ferramenta", "Nmap"))

    # Ataques compostos
    g.adicionar_no(No("atk_bypass_login", "Ataque", "Bypass de login"))
    g.adicionar_no(No("atk_roubo_sessao_cliente", "Ataque", "Roubo de sessao de cliente"))

    # Relacoes aplicacao e endpoints
    g.adicionar_relacao("app_loja", "ep_login", "TEM_ENDPOINT")
    g.adicionar_relacao("app_loja", "ep_produto", "TEM_ENDPOINT")
    g.adicionar_relacao("app_loja", "ep_carrinho", "TEM_ENDPOINT")
    g.adicionar_relacao("app_loja", "ep_checkout", "TEM_ENDPOINT")

    # Relacoes endpoint e parametros
    g.adicionar_relacao("ep_login", "param_username", "TEM_PARAMETRO")
    g.adicionar_relacao("ep_login", "param_password", "TEM_PARAMETRO")
    g.adicionar_relacao("ep_produto", "param_busca", "TEM_PARAMETRO")
    g.adicionar_relacao("ep_produto", "param_id_produto", "TEM_PARAMETRO")
    g.adicionar_relacao("ep_carrinho", "param_id_produto", "TEM_PARAMETRO")
    g.adicionar_relacao("ep_carrinho", "param_quantidade", "TEM_PARAMETRO")

    # Relacoes vulnerabilidade contexto
    g.adicionar_relacao("vul_sqli_login_username", "ep_login", "ESTA_NO_ENDPOINT")
    g.adicionar_relacao("vul_sqli_login_username", "param_username", "AFETA_PARAMETRO")
    g.adicionar_relacao("vul_sqli_login_username", "tv_sqli", "E_DO_TIPO")
    g.adicionar_relacao("vul_sqli_login_username", "imp_exposicao_clientes", "GERA_IMPACTO")

    g.adicionar_relacao("vul_sqli_busca_produto", "ep_produto", "ESTA_NO_ENDPOINT")
    g.adicionar_relacao("vul_sqli_busca_produto", "param_busca", "AFETA_PARAMETRO")
    g.adicionar_relacao("vul_sqli_busca_produto", "tv_sqli", "E_DO_TIPO")
    g.adicionar_relacao("vul_sqli_busca_produto", "imp_exposicao_clientes", "GERA_IMPACTO")

    g.adicionar_relacao("vul_xss_busca_produto", "ep_produto", "ESTA_NO_ENDPOINT")
    g.adicionar_relacao("vul_xss_busca_produto", "param_busca", "AFETA_PARAMETRO")
    g.adicionar_relacao("vul_xss_busca_produto", "tv_xss_refletido", "E_DO_TIPO")
    g.adicionar_relacao("vul_xss_busca_produto", "imp_roubo_sessao", "GERA_IMPACTO")

    g.adicionar_relacao("vul_idor_carrinho_id_produto", "ep_carrinho", "ESTA_NO_ENDPOINT")
    g.adicionar_relacao("vul_idor_carrinho_id_produto", "param_id_produto", "AFETA_PARAMETRO")
    g.adicionar_relacao("vul_idor_carrinho_id_produto", "tv_idor", "E_DO_TIPO")
    g.adicionar_relacao("vul_idor_carrinho_id_produto", "imp_manipulacao_pedidos", "GERA_IMPACTO")

    # Ferramentas usadas
    g.adicionar_relacao("vul_sqli_login_username", "tool_burp", "FOI_ENCONTRADA_COM")
    g.adicionar_relacao("vul_sqli_busca_produto", "tool_burp", "FOI_ENCONTRADA_COM")
    g.adicionar_relacao("vul_xss_busca_produto", "tool_burp", "FOI_ENCONTRADA_COM")
    g.adicionar_relacao("vul_idor_carrinho_id_produto", "tool_burp", "FOI_ENCONTRADA_COM")

    # Ataques compostos
    g.adicionar_relacao("atk_bypass_login", "vul_sqli_login_username", "EXPLORA_VULNERABILIDADE")
    g.adicionar_relacao("atk_bypass_login", "imp_exposicao_clientes", "PRODUZ_IMPACTO")

    g.adicionar_relacao("atk_roubo_sessao_cliente", "vul_xss_busca_produto", "EXPLORA_VULNERABILIDADE")
    g.adicionar_relacao("atk_roubo_sessao_cliente", "imp_roubo_sessao", "PRODUZ_IMPACTO")

    return g

def formatar_lista_rotulos(nos: list[No]) -> str:
    if not nos:
        return "nao mapeado"
    return ", ".join(n.rotulo for n in nos)


def exibir_vulnerabilidades_por_endpoint(grafo: GrafoConhecimento, endpoint_id: str, nome_amigavel: str) -> None:
    print(f"Vulnerabilidades no endpoint {nome_amigavel}")
    print()

    vulnerabilidades = grafo.vulnerabilidades_por_endpoint(endpoint_id)
    if not vulnerabilidades:
        print("Nenhuma vulnerabilidade cadastrada para este endpoint")
        print()
        return

    for vul in vulnerabilidades:
        tipos = grafo.tipos_de_vulnerabilidade(vul.id)
        impactos = grafo.impactos_de_vulnerabilidade(vul.id)

        print(f"• {vul.rotulo}")
        print(f"   id: {vul.id}")
        print(f"   tipo: {formatar_lista_rotulos(tipos)}")
        print(f"   impacto: {formatar_lista_rotulos(impactos)}")
        print()



if __name__ == "__main__":
    grafo = criar_grafo_exemplo()

    exibir_vulnerabilidades_por_endpoint(grafo, "ep_login", "login")
    print()
    exibir_vulnerabilidades_por_endpoint(grafo, "ep_produto", "produto")
    print()

    print("Impactos da vulnerabilidade de XSS na busca")
    impactos_xss = grafo.impactos_de_vulnerabilidade("vul_xss_busca_produto")
    for imp in impactos_xss:
        print(f"• {imp.rotulo}")

    # Exportar grafo para DOT
    grafo.exportar_para_dot("grafo_ciberseguranca.dot")
    print("\nArquivo grafo_ciberseguranca.dot gerado na pasta do projeto.")
