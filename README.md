# Web Scanner: Rastreador de Vulnerabilidades Web

O **Web Scanner** é uma ferramenta de análise de segurança para aplicações web, desenvolvida em Python. Ele automatiza o processo de varredura de portas, serviços e vulnerabilidades conhecidas (CVEs) utilizando o **Nmap**, e realiza uma análise aprofundada em sites WordPress com o **WPScan**.

Os resultados são compilados e apresentados em um **dashboard web local e interativo**, criado com Flask, facilitando a visualização e interpretação dos dados.

## Funcionalidades Principais

- **Scanner de Portas e Serviços**: Utiliza o Nmap para uma varredura completa, identificando portas abertas, serviços e versões.
- **Detecção de Vulnerabilidades (CVEs)**: Integra o script `vulners` do Nmap para correlacionar serviços com vulnerabilidades conhecidas.
- **Detecção de WordPress**: Identifica automaticamente se o alvo é um site WordPress.
- **Análise com WPScan**: Oferece varreduras "rápida" e "completa" em alvos WordPress para encontrar plugins, temas, usuários e vulnerabilidades específicas.
- **Dashboard Interativo**: Inicia um servidor web local (Flask) para exibir os resultados em uma interface amigável com gráficos (Chart.js), modo claro/escuro e opção de download do relatório em HTML.

## Instalação e Pré-requisitos

Antes de executar o script, garanta que você tenha os seguintes pré-requisitos instalados em seu sistema:

1.  **Python 3**:
    ```bash
    sudo apt update
    sudo apt install python3 python3-pip
    ```

2.  **Nmap**:
    ```bash
    sudo apt install nmap
    ```

3.  **Ruby e WPScan**: Necessário para a análise aprofundada de WordPress.
    ```bash
    # Instale o Ruby e as dependências de desenvolvimento
    sudo apt install ruby-full ruby-dev build-essential

    # Instale o WPScan
    sudo gem install wpscan
    ```

## Como Usar

1.  Clone o repositório.
    ```bash
    git clone [https://github.com/pedrohsmelo/webscanner.git](https://github.com/pedrohsmelo/webscanner.git)
    cd webscanner
    ```

2.  Execute o script a partir do seu terminal:
    ```bash
    python3 web_scanner.py
    ```

3.  O script irá primeiro verificar e instalar as bibliotecas Python faltantes.

4.  Em seguida, ele solicitará o **domínio do alvo** que você deseja analisar.
    ```
    Informe o domínio (ex: [https://site.com](https://site.com)):
    ```

5.  Se o alvo for detectado como WordPress, ele perguntará se deseja prosseguir com a varredura do WPScan e qual o tipo de scan (rápido ou completo).

6.  Ao final da análise, um servidor web será iniciado e uma aba será aberta automaticamente no seu navegador, exibindo o dashboard com os resultados.

## O Dashboard

O dashboard fornece uma visão clara e organizada dos dados coletados:

- **Resumo Geral**: Métricas principais como total de CVEs, portas abertas e se o WordPress foi detectado.
- **Gráficos Dinâmicos**: Visualizações sobre a distribuição de portas e a quantidade de serviços vulneráveis.
- **Análise WordPress**: Se aplicável, mostra a versão do WP, contagem de plugins/temas desatualizados, usuários enumerados e gráficos detalhados.
- **Detalhes do Nmap**: Uma lista completa de todas as portas encontradas, os serviços rodando e as vulnerabilidades (CVEs) associadas a cada um.
- **Exportação de Relatório**: Um botão permite baixar o relatório completo como um único arquivo HTML.
- **Modo Claro/Escuro**: Alterne entre os temas para melhor visualização.

![Exemplo do Dashboard](https://raw.githubusercontent.com/pedrohsmelo/webscanner/main/assets/dashboard.png)

## ⚠️ Aviso Legal

Esta ferramenta foi criada para fins educacionais e para ser utilizada em auditorias de segurança autorizadas. O mau uso desta ferramenta para atacar alvos sem consentimento prévio é ilegal. O desenvolvedor não se responsabiliza por qualquer dano ou uso indevido. Use-a por sua conta e risco.

## 👨‍💻 Créditos

Desenvolvido por **Cyber Rasta**.
