#!/usr/bin/env python3
'''
 █████   ███   █████          █████         █████████
░░███   ░███  ░░███          ░░███         ███░░░░░███
 ░███   ░███   ░███   ██████  ░███████    ░███    ░░░   ██████   ██████   ████████   ████████    ██████  ████████
 ░███   ░███   ░███  ███░░███ ░███░░███   ░░█████████  ███░░███ ░░░░░███ ░░███░░███ ░░███░░███  ███░░███░░███░░███
 ░░███  █████  ███  ░███████  ░███ ░███    ░░░░░░░░███░███ ░░░   ███████  ░███ ░███  ░███ ░███ ░███████  ░███ ░░░
  ░░░█████░█████░   ░███░░░   ░███ ░███    ███    ░███░███  ███ ███░░███  ░███ ░███  ░███ ░███ ░███░░░   ░███
    ░░███ ░░███     ░░██████  ████████    ░░█████████ ░░██████ ░░████████ ████ █████ ████ █████░░██████  █████
     ░░░   ░░░       ░░░░░░  ░░░░░░░░      ░░░░░░░░░   ░░░░░░   ░░░░░░░░ ░░░░ ░░░░░ ░░░░ ░░░░░  ░░░░░░  ░░░░░
                                                                                                        by Cyber Rasta
'''

import subprocess
import sys
import os
import json
import nmap
import webbrowser
import platform
import shutil
import signal
import socket
from threading import Thread

SCAN_FILE = 'scan_result.json'
TIMEOUT_SECONDS = 4500
HEADERS_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"

# Mecanismo de Timed Out
def TimeoutHandler(signum, frame):
    print("\n[!] Tempo limite foi atingido. Encerrando a ferramenta.")
    os._exit(1)

# Coletando o IP da rede
def GetLanIp():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

# Verificando e instalando as deps
def SetupDependencies():
    print("[*] Verificando dependências...")
    try:
        import flask
        import nmap
    except ImportError:
        print("[*] Instalando bibliotecas Python necessárias (Flask, python-nmap)...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", "flask", "python-nmap"], stdout=subprocess.DEVNULL)

    if shutil.which("nmap") is None:
        print("[!] Nmap não encontrado. Tente instalar com 'sudo apt install nmap' ou o gerenciador de pacotes da sua distribuição.")
        sys.exit(1)

def CheckWpscan():
    if shutil.which("wpscan") is not None:
        return
    print("\n[!] WPScan não encontrado. Esta ferramenta é necessária para a análise aprofundada de WordPress.")
    if shutil.which("ruby") is None:
        print("[!] Ruby não está instalado. Siga estes passos:")
        print("    1. Instale o Ruby e suas ferramentas de desenvolvimento. Em sistemas baseados em Debian/Ubuntu:")
        print("       sudo apt update && sudo apt install ruby-full ruby-dev build-essential")
        print("    2. Após instalar o Ruby, instale o WPScan com o comando abaixo.")
    print("\n[*] Para instalar o WPScan, execute o seguinte comando no seu terminal:")
    print("    sudo gem install wpscan")
    print("\n[*] Após a instalação, execute a ferramenta novamente.")
    sys.exit(1)

# Lógica de Scan
def ScanPortsAndVulns(target):
    print("[*] Iniciando varredura (isso pode levar alguns minutos)...")
    scanner = nmap.PortScanner()
    hostname = target.split('//')[-1].split('/')[0]
    args = f"-sV -p- --script vulners,http-generator --script-args http.useragent='{HEADERS_UA}'"
    print(f"[*] Executando uma varredura em {hostname}")
    try:
        scanner.scan(hostname, arguments=args)
    except nmap.nmap.PortScannerError as e:
        print(f"[!] Erro no Nmap: {e}. Verifique o alvo ou as permissões.")
        return [], [], 0, False
    
    results, scanned_ports, total_cve_count, is_wordpress_detected = [], [], 0, False
    
    if not scanner.all_hosts():
        print("[!] Nenhum host encontrado. O alvo pode estar offline ou bloqueando pings.")
        return [], [], 0, False
        
    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto].keys()
            scanned_ports.extend(ports)
            for port in sorted(list(ports)):
                svc = scanner[host][proto][port]
                if 'WordPress' in svc.get('script', {}).get('http-generator', ''):
                    is_wordpress_detected = True
                
                cves_data = svc.get('script', {}).get('vulners', '')
                
                cve_list = [item.strip() for item in cves_data.split('\n') if item.strip()] if cves_data else []
                
                port_cve_total = len(cve_list)
                total_cve_count += port_cve_total
                
                results.append({
                    'port': port, 
                    'service': svc.get('name', ''), 
                    'product': svc.get('product', ''), 
                    'version': svc.get('version', ''), 
                    'cves': cve_list,
                    'cve_count': port_cve_total 
                })

    return results, list(set(scanned_ports)), total_cve_count, is_wordpress_detected

# Definindo a execução do WP Scan
def RunWpscan(target, api_key, scan_type='completa'):
    print(f"[*] Executando varredura {scan_type} com WPScan...")
    if scan_type == 'rapida':
        enumeration_args = 'vp,vt'
    else:
        enumeration_args = 'vp,vt,u'

    cmd = [
        'wpscan', '--url', target, '--format', 'json',
        '--enumerate', enumeration_args,
        '--random-user-agent'
    ]
    if api_key:
        cmd.extend(['--api-token', api_key])
    res = subprocess.run(cmd, capture_output=True, text=True, check=False)
    try:
        json_output_start = res.stdout.find('{')
        if json_output_start != -1:
            return json.loads(res.stdout[json_output_start:])
        return {'error': 'Falha ao processar output do WPScan.', 'details': res.stdout}
    except json.JSONDecodeError:
        return {'error': 'Falha ao decodificar JSON do WPScan.', 'details': res.stdout}

# Definindo o fluxo prinxipal e a interface
def AskAndScan():
    target = input("Informe o domínio (ex: https://site.com): ").strip()
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target

    nmap_data, scanned_ports, total_cves, is_wordpress_by_nmap = ScanPortsAndVulns(target)
    
    run_wpscan_scan = False 

    if is_wordpress_by_nmap:
        print("\n[✔] WordPress detectado automaticamente pelo Nmap!")
        prompt = input("    Deseja realizar uma varredura aprofundada com o WPScan? [S/n]: ").strip().lower()
        if prompt in ['s', 'sim', '']:
            run_wpscan_scan = True
    else:
        print("\n[!] O Nmap não detectou o WordPress automaticamente.")
        prompt = input("    Deseja forçar a verificação para WordPress mesmo assim? [s/N]: ").strip().lower()
        if prompt in ['s', 'sim']:
            run_wpscan_scan = True

    wpscan_data = {}
    is_wp_confirmed = is_wordpress_by_nmap

    if run_wpscan_scan:
        CheckWpscan()
        scan_type_choice = input("Escolha o tipo de varredura do WPScan:\n  [1] Rápida (Apenas Vulnerabilidades)\n  [2] Completa (Vulnerabilidades + Usuários)\nSua escolha: ").strip()
        scan_type = 'rapida' if scan_type_choice == '1' else 'completa'
        print("\n[!] Para uma análise completa de vulnerabilidades, uma API do WPScan é recomendada.")
        print("    Acesse https://wpscan.com/api para obter sua chave gratuita.")
        key = input("    Cole sua API Key (ou pressione Enter para escanear sem ela): ").strip()
        wpscan_data = RunWpscan(target, key, scan_type)
        if wpscan_data and not wpscan_data.get('error'):
            is_wp_confirmed = True
            
    report = {
        'site': target, 'wordpress_detected': is_wp_confirmed,
        'wpscan_run': run_wpscan_scan, 'wpscan': wpscan_data,
        'nmap': nmap_data, 'scanned_ports': sorted(scanned_ports),
        'total_cves': total_cves
    }

    with open(SCAN_FILE, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=4, ensure_ascii=False)
    
    print(f"\n[✔] Relatório salvo em {SCAN_FILE}")
    StartServer(report)

# Definindo o Dashboard no server Flask
def StartServer(data):
    from flask import Flask, render_template_string
    app = Flask(__name__)

    HTML_TEMPLATE = """
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Dashboard de Segurança | {{ site }}</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
        <style>
            :root {
                --bg-color: #0f172a; --card-color: #1e293b; --border-color: #334155;
                --text-color: #e2e8f0; --text-muted: #94a3b8; --accent-color: #38bdf8;
                --success-color: #22c55e; --warning-color: #f59e0b; --danger-color: #f43f5e;
                --font-family: 'Inter', sans-serif; --header-bg: rgba(15, 23, 42, 0.8);
                --shadow-color: rgba(0, 0, 0, 0.2);
            }
            body.light-mode {
                --bg-color: #f1f5f9; --card-color: #ffffff; --border-color: #e2e8f0;
                --text-color: #1e293b; --text-muted: #64748b; --accent-color: #0ea5e9;
                --success-color: #16a34a; --warning-color: #d97706; --danger-color: #dc2626;
                --header-bg: rgba(241, 245, 249, 0.8); --shadow-color: rgba(100, 116, 139, 0.12);
            }
            body {
                background-color: var(--bg-color); color: var(--text-color); font-family: var(--font-family);
                margin: 0; padding: 2rem; transition: background-color 0.3s, color 0.3s;
            }
            .container { max-width: 1400px; margin: auto; display: flex; flex-direction: column; gap: 1.5rem; }
            header {
                display: flex; justify-content: space-between; align-items: center;
                border-bottom: 1px solid var(--border-color); padding-bottom: 1rem;
                position: sticky; top: 0; background-color: var(--header-bg); backdrop-filter: blur(10px);
                z-index: 1000; padding: 1rem 2rem; margin: -2rem -2rem 1rem -2rem;
            }
            header h1 { font-size: 1.875rem; font-weight: 700; margin: 0; }
            header h1 span { color: var(--text-muted); font-weight: 400; font-size: 1.125rem; display: block; margin-top: 0.25rem; }
            .header-buttons { display: flex; gap: 1rem; }
            .action-btn { background-color: var(--accent-color); color: #fff; border: none; padding: 0.6rem 1.2rem; border-radius: 8px; cursor: pointer; font-weight: 600; transition: background-color 0.3s ease, box-shadow 0.3s ease; }
            .action-btn:hover { filter: brightness(1.1); }
            .theme-toggle { background-color: var(--card-color); border: 1px solid var(--border-color); color: var(--text-muted); }
            .theme-toggle:hover { border-color: var(--accent-color); color: var(--accent-color); }
            .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 1.5rem; }
            .card {
                background-color: var(--card-color); border: 1px solid var(--border-color);
                border-radius: 1rem; padding: 1.5rem; color: var(--text-color);
                box-shadow: 0 4px 10px -2px var(--shadow-color);
                transition: background-color 0.3s, border-color 0.3s, box-shadow 0.3s;
            }
            .card-header { font-size: 1.125rem; font-weight: 600; margin: 0 0 1.5rem 0; color: var(--text-color); }
            .summary-item { display: flex; justify-content: space-between; align-items: center; padding: 1rem 0; border-bottom: 1px solid var(--border-color); }
            .summary-item:first-of-type { padding-top: 0; }
            .summary-item:last-child { border-bottom: none; padding-bottom: 0; }
            .summary-item strong { font-weight: 500; color: var(--text-muted); }
            .summary-item span { font-weight: 700; font-size: 2rem; }
            .summary-item .bool-yes { color: var(--warning-color); font-size: 1.25rem }
            .summary-item .bool-no { color: var(--success-color); font-size: 1.25rem }
            .scan-results-container { max-height: 450px; overflow-y: auto; display: flex; flex-direction: column; gap: 1rem; }
            .result-item {
                display: flex; flex-wrap: wrap; justify-content: space-between;
                padding: 1rem 0; border-bottom: 1px solid var(--border-color);
            }
            .result-item:last-child { border-bottom: none; }
            .info-block { flex: 1; min-width: 200px; padding-right: 1rem; }
            .info-block .port { font-size: 1.25rem; font-weight: 700; color: var(--accent-color); }
            .info-block .service { color: var(--text-muted); }
            .info-block .product { font-size: 0.9rem; }
            .vuln-block { flex: 2; min-width: 300px; text-align: left; }
            details { background-color: transparent; border: none; margin: 0; }
            summary { padding: 0.5rem; font-weight: 600; cursor: pointer; border-radius: 6px; transition: background-color 0.2s; display: inline-block; }
            summary:hover { background-color: var(--border-color); }
            .cve-list { list-style-type: none; padding: 0.5rem 0 0 0; margin: 0; }
            .cve-list li { background-color: color-mix(in srgb, var(--danger-color) 15%, transparent); color: var(--danger-color); padding: 0.3rem 0.6rem; border-radius: 5px; margin-top: 5px; font-size: 0.85rem; display: inline-block; font-weight: 500; }
            .no-cve { color: var(--success-color); font-weight: 500; }
            .chart-container { position: relative; height: 250px; width: 100%; }
            .wp-charts { display: flex; gap: 2rem; justify-content: center; align-items: center; margin-top: 1.5rem; flex-wrap: wrap; }
            .wp-chart-container { max-width: 200px; }
            .status-ok { color: var(--success-color); }
            .status-outdated { color: var(--warning-color); font-weight: bold; }
            .user-list { list-style: none; padding: 0; column-count: 3; }
        </style>
    </head>
    <body>
        <div class="container">
            <header>
                <h1>Dashboard de Segurança<span>{{ site }}</span></h1>
                <div class="header-buttons">
                    <button id="theme-toggle" class="action-btn theme-toggle">🌓</button>
                    <button class="action-btn" onclick="saveReport()">📥 Baixar Relatório</button>
                </div>
            </header>
            <div class="grid">
                <div class="card">
                    <div class="card-header">📊 Resumo Geral</div>
                    <div class="summary-item"><strong>Total de CVEs Encontradas</strong><span style="color: var(--danger-color);">{{ total_cves }}</span></div>
                    <div class="summary-item"><strong>Portas Abertas</strong><span style="color: var(--warning-color);">{{ nmap|length }}</span></div>
                    <div class="summary-item"><strong>WordPress Detectado</strong><span class="{{ 'bool-yes' if wordpress_detected else 'bool-no' }}">{{ 'Sim' if wordpress_detected else 'Não' }}</span></div>
                </div>
                <div class="card">
                    <div class="card-header">📈 Análise de Portas</div>
                    <div class="chart-container">
                        <canvas id="portsChart"></canvas>
                    </div>
                </div>
                <div class="card">
                    <div class="card-header">☣️ Análise de CVEs</div>
                    <div class="chart-container">
                        <canvas id="cvesChart"></canvas>
                    </div>
                </div>
            </div>

            {% if wordpress_detected and wpscan_run and wpscan and not wpscan.get('error') %}
            <div class="card">
                <div class="card-header">🤖 Análise Aprofundada do WordPress</div>
                
                {% set plugins = wpscan.get('plugins', {}) %}
                {% set themes = wpscan.get('themes', {}) %}
                {% set users = wpscan.get('users', {}) %}

                {% set outdated_plugins_count = namespace(value=0) %}
                {% for slug, p in plugins.items() if p.version and p.latest_version and p.version.number != p.latest_version %}
                    {% set outdated_plugins_count.value = outdated_plugins_count.value + 1 %}
                {% endfor %}

                {% set outdated_themes_count = namespace(value=0) %}
                {% for slug, t in themes.items() if t.version and t.latest_version and t.version.number != t.latest_version %}
                    {% set outdated_themes_count.value = outdated_themes_count.value + 1 %}
                {% endfor %}

                <div class="grid">
                    <div><strong>Versão do WP:</strong><br>{{ wpscan.version.number if wpscan.version else 'N/A' }}</div>
                    <div><strong>Plugins Desatualizados:</strong><br><span style="color: var(--warning-color);">{{ outdated_plugins_count.value }} de {{ plugins|length }}</span></div>
                    <div><strong>Temas Desatualizados:</strong><br><span style="color: var(--warning-color);">{{ outdated_themes_count.value }} de {{ themes|length }}</span></div>
                    <div><strong>Usuários Encontrados:</strong><br><span style="color: var(--danger-color);">{{ users|length }}</span></div>
                </div>

                <div class="wp-charts">
                    {% if plugins %}
                    <div class="wp-chart-container"><canvas id="pluginsChart"></canvas></div>
                    {% endif %}
                    {% if themes %}
                    <div class="wp-chart-container"><canvas id="themesChart"></canvas></div>
                    {% endif %}
                </div>

                {% if plugins %}<details><summary>Plugins Identificados ({{ plugins|length }})</summary><div class="scan-results-container">{% for slug, p in plugins.items() %}<div class="result-item"><div class="info-block">{{ p.slug }}</div><div class="vuln-block"><strong>Versão:</strong> {{ p.version.number if p.version else 'N/A' }}<br>{% if p.version and p.latest_version and p.version.number == p.latest_version %}<span class="status-ok">✔️ Atualizado</span>{% elif p.version and p.latest_version %}<span class="status-outdated">⚠️ Desatualizado (Última: {{ p.latest_version }})</span>{% else %}<span>-</span>{% endif %}</div></div>{% endfor %}</div></details>{% endif %}
                {% if themes %}<details><summary>Temas Identificados ({{ themes|length }})</summary><div class="scan-results-container">{% for slug, t in themes.items() %}<div class="result-item"><div class="info-block">{{ t.slug }}</div><div class="vuln-block"><strong>Versão:</strong> {{ t.version.number if t.version else 'N/A' }}<br>{% if t.version and t.latest_version and t.version.number == t.latest_version %}<span class="status-ok">✔️ Atualizado</span>{% elif t.version and t.latest_version %}<span class="status-outdated">⚠️ Desatualizado (Última: {{ t.latest_version }})</span>{% else %}<span>-</span>{% endif %}</div></div>{% endfor %}</div></details>{% endif %}
                {% if users %}<details><summary>Usuários Enumerados ({{ users|length }})</summary><ul class="user-list">{% for username, data in users.items() %}<li>{{ username }}</li>{% endfor %}</ul></details>{% endif %}
            </div>
            {% endif %}
            <div class="card">
                <div class="card-header">🔌 Detalhes das Portas (Nmap)</div>
                <div class="scan-results-container">
                    {% for item in nmap %}
                    <div class="result-item">
                        <div class="info-block">
                            <div class="port">{{ item.port }}</div>
                            <div class="service">{{ item.service }}</div>
                            <div class="product">{{ item.product }} {{ item.version }}</div>
                        </div>
                        <div class="vuln-block">
                            {% if item.cve_count > 0 %}
                                <details>
                                    <summary>Vulnerabilidades Encontradas ({{ item.cve_count }})</summary>
                                    <ul class="cve-list">{% for cve in item.cves %}<li>{{ cve.split(' ')[0] }}</li>{% endfor %}</ul>
                                </details>
                            {% else %}
                                <span class="no-cve">Nenhuma vulnerabilidade detectada</span>
                            {% endif %}
                        </div>
                    </div>
                    {% endfor %}
                </div>
            </div>
        </div>

        <script>
            function saveReport() {
                const pageHTML = document.documentElement.outerHTML;
                const blob = new Blob([pageHTML], { type: 'text/html' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'relatorio_seguranca_{{ site }}.html';
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
            }
            const themeToggle = document.getElementById('theme-toggle');
            themeToggle.addEventListener('click', () => {
                document.body.classList.toggle('light-mode');
                const theme = document.body.classList.contains('light-mode') ? 'light' : 'dark';
                localStorage.setItem('theme', theme);
                location.reload();
            });
            document.addEventListener('DOMContentLoaded', () => {
                const isLightMode = localStorage.getItem('theme') === 'light';
                if (isLightMode) {
                    document.body.classList.add('light-mode');
                }
                const DANGER_COLOR = getComputedStyle(document.body).getPropertyValue('--danger-color').trim();
                const SUCCESS_COLOR = getComputedStyle(document.body).getPropertyValue('--success-color').trim();
                const WARNING_COLOR = getComputedStyle(document.body).getPropertyValue('--warning-color').trim();
                const MUTED_COLOR = isLightMode ? '#e2e8f0' : '#334155';
                const chartTextColor = getComputedStyle(document.body).getPropertyValue('--text-color').trim();
                const chartBorderColor = getComputedStyle(document.body).getPropertyValue('--border-color').trim();
                Chart.defaults.color = chartTextColor;
                new Chart(document.getElementById('portsChart'), {
                    type: 'doughnut',
                    data: {
                        labels: ['Portas Abertas', 'Portas Fechadas/Filtradas'],
                        datasets: [{ data: [{{ nmap|length }}, {{ (scanned_ports|length) - (nmap|length) }}], backgroundColor: [DANGER_COLOR, MUTED_COLOR], borderWidth: 0 }]
                    },
                    options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'top' } } }
                });
                const portsWithCVEs = {{ nmap | selectattr('cve_count', '>', 0) | list | length }};
                const portsWithoutCVEs = {{ nmap|length }} - portsWithCVEs;
                new Chart(document.getElementById('cvesChart'), {
                    type: 'bar',
                    data: {
                        labels: ['Serviços com CVEs', 'Serviços sem CVEs'],
                        datasets: [{ label: 'Contagem de Serviços', data: [portsWithCVEs, portsWithoutCVEs], backgroundColor: [DANGER_COLOR, SUCCESS_COLOR] }]
                    },
                    options: {
                        indexAxis: 'y', responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } },
                        scales: { x: { grid: { color: chartBorderColor } }, y: { grid: { color: chartBorderColor } } }
                    }
                });

                {% if wordpress_detected and wpscan_run and wpscan and not wpscan.get('error') %}
                const outdatedPlugins = {{ outdated_plugins_count.value }};
                const updatedPlugins = {{ plugins|length }} - outdatedPlugins;
                new Chart(document.getElementById('pluginsChart'), {
                    type: 'doughnut',
                    data: {
                        labels: ['Desatualizados', 'Atualizados'],
                        datasets: [{ data: [outdatedPlugins, updatedPlugins], backgroundColor: [WARNING_COLOR, SUCCESS_COLOR], borderWidth: 0 }]
                    },
                    options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'bottom' }, title: { display: true, text: 'Plugins' } } }
                });
                const outdatedThemes = {{ outdated_themes_count.value }};
                const updatedThemes = {{ themes|length }} - outdatedThemes;
                new Chart(document.getElementById('themesChart'), {
                    type: 'doughnut',
                    data: {
                        labels: ['Desatualizados', 'Atualizados'],
                        datasets: [{ data: [outdatedThemes, updatedThemes], backgroundColor: [WARNING_COLOR, SUCCESS_COLOR], borderWidth: 0 }]
                    },
                    options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'bottom' }, title: { display: true, text: 'Temas' } } }
                });
                {% endif %}
            });
        </script>
    </body>
    </html>
    """
    
    @app.route('/')
    def Home():
        return render_template_string(HTML_TEMPLATE, **data)

    host_ip = GetLanIp()
    port = 5000

    print("\n[*] Iniciando servidor web para exibir o dashboard...")
    print(f"[✔] Dashboard acessível em:")
    print(f"    - Localmente: http://127.0.0.1:{port}")
    if host_ip != "127.0.0.1":
        print(f"    - Na sua rede: http://{host_ip}:{port}")
    
    webbrowser.open(f'http://127.0.0.1:{port}', new=2)
    app.run(host='0.0.0.0', port=port, debug=False)


if __name__ == '__main__':
    if platform.system() != "Windows":
        signal.signal(signal.SIGALRM, TimeoutHandler)
        signal.alarm(TIMEOUT_SECONDS)
    
    print("Iniciando Ferramenta de Análise de Segurança by Cyber Rasta")
    print("-" * 60)
    
    SetupDependencies()
    try:
        AskAndScan()
    except KeyboardInterrupt:
        print("\n[!] Varredura interrompida pelo usuário. Encerrando.")
        sys.exit(0)
    finally:
        if platform.system() != "Windows":
            signal.alarm(0)
    
    print("[*] Dashboard fechado. Encerrando a aplicação.")