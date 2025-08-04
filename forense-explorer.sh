#!/bin/bash

# Forensic Explorer - Ferramenta de Análise Forense Digital
# Versão 1.0
# Autor: [Seu Nome]
# Licença: MIT

# Cores para o menu
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Verifica se é root
if [ "$(id -u)" != "0" ]; then
   echo -e "${RED}[ERRO] Este script deve ser executado como root!${NC}" 
   exit 1
fi

# Cria diretório de saída
OUTPUT_DIR="forensic_report_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"

# Função para coletar informações do sistema
system_info() {
    echo -e "${GREEN}[+] Coletando informações do sistema...${NC}"
    echo "Data e Hora: $(date)" > "$OUTPUT_DIR/system_info.txt"
    echo "Hostname: $(hostname)" >> "$OUTPUT_DIR/system_info.txt"
    echo "Sistema Operacional: $(uname -a)" >> "$OUTPUT_DIR/system_info.txt"
    echo "Versão do Kernel: $(cat /proc/version)" >> "$OUTPUT_DIR/system_info.txt"
    echo "Uptime: $(uptime)" >> "$OUTPUT_DIR/system_info.txt"
    echo -e "${BLUE}[*] Informações do sistema salvas em $OUTPUT_DIR/system_info.txt${NC}"
}

# Função para analisar processos
process_analysis() {
    echo -e "${GREEN}[+] Analisando processos em execução...${NC}"
    ps aux > "$OUTPUT_DIR/running_processes.txt"
    echo -e "${BLUE}[*] Lista de processos salva em $OUTPUT_DIR/running_processes.txt${NC}"
}

# Função para analisar conexões de rede
network_analysis() {
    echo -e "${GREEN}[+] Analisando conexões de rede...${NC}"
    netstat -tulnp > "$OUTPUT_DIR/network_connections.txt"
    ss -tulnp >> "$OUTPUT_DIR/network_connections.txt"
    echo -e "${BLUE}[*] Conexões de rede salvas em $OUTPUT_DIR/network_connections.txt${NC}"
}

# Função para analisar arquivos de log
log_analysis() {
    echo -e "${GREEN}[+] Analisando arquivos de log...${NC}"
    mkdir -p "$OUTPUT_DIR/logs"
    
    # Coletar logs comuns
    cp /var/log/auth.log "$OUTPUT_DIR/logs/" 2>/dev/null
    cp /var/log/syslog "$OUTPUT_DIR/logs/" 2>/dev/null
    cp /var/log/dmesg "$OUTPUT_DIR/logs/" 2>/dev/null
    cp /var/log/secure "$OUTPUT_DIR/logs/" 2>/dev/null  # Para RHEL/CentOS
    
    # Coletar logs do kernel
    dmesg > "$OUTPUT_DIR/logs/dmesg_current.txt"
    
    echo -e "${BLUE}[*] Logs coletados em $OUTPUT_DIR/logs/${NC}"
}

# Função para analisar usuários
user_analysis() {
    echo -e "${GREEN}[+] Analisando usuários do sistema...${NC}"
    echo "Usuários logados:" > "$OUTPUT_DIR/user_info.txt"
    who >> "$OUTPUT_DIR/user_info.txt"
    echo "" >> "$OUTPUT_DIR/user_info.txt"
    echo "Últimos logins:" >> "$OUTPUT_DIR/user_info.txt"
    last >> "$OUTPUT_DIR/user_info.txt"
    echo "" >> "$OUTPUT_DIR/user_info.txt"
    echo "Usuários com shell válido:" >> "$OUTPUT_DIR/user_info.txt"
    grep -v "/nologin\|/false" /etc/passwd >> "$OUTPUT_DIR/user_info.txt"
    echo "" >> "$OUTPUT_DIR/user_info.txt"
    echo "Usuários com privilégios sudo:" >> "$OUTPUT_DIR/user_info.txt"
    grep -Po '^sudo.+:\K.*$' /etc/group >> "$OUTPUT_DIR/user_info.txt"
    
    echo -e "${BLUE}[*] Informações de usuários salvas em $OUTPUT_DIR/user_info.txt${NC}"
}

# Função para analisar cron jobs
cron_analysis() {
    echo -e "${GREEN}[+] Analisando tarefas agendadas...${NC}"
    mkdir -p "$OUTPUT_DIR/cron"
    
    # Coletar cron jobs de todos os usuários
    for user in $(cut -f1 -d: /etc/passwd); do
        crontab -u "$user" -l > "$OUTPUT_DIR/cron/cron_$user.txt" 2>/dev/null
    done
    
    # Coletar arquivos do sistema
    cp -r /etc/cron* "$OUTPUT_DIR/cron/"
    
    echo -e "${BLUE}[*] Tarefas agendadas salvas em $OUTPUT_DIR/cron/${NC}"
}

# Função para analisar serviços
service_analysis() {
    echo -e "${GREEN}[+] Analisando serviços do sistema...${NC}"
    
    # Verifica qual sistema de init está em uso
    if [ -x "$(command -v systemctl)" ]; then
        systemctl list-unit-files --type=service > "$OUTPUT_DIR/services.txt"
        systemctl list-units --type=service --state=running >> "$OUTPUT_DIR/services.txt"
    elif [ -x "$(command -v service)" ]; then
        service --status-all > "$OUTPUT_DIR/services.txt"
    else
        echo "Não foi possível determinar o sistema de init" > "$OUTPUT_DIR/services.txt"
    fi
    
    echo -e "${BLUE}[*] Informações de serviços salvas em $OUTPUT_DIR/services.txt${NC}"
}

# Função para buscar arquivos suspeitos
file_analysis() {
    echo -e "${GREEN}[+] Buscando arquivos suspeitos...${NC}"
    mkdir -p "$OUTPUT_DIR/file_analysis"
    
    # Buscar arquivos executáveis em diretórios comuns
    find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec file {} \; > "$OUTPUT_DIR/file_analysis/executables.txt"
    
    # Buscar arquivos com SUID/SGID
    find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -la {} \; 2>/dev/null > "$OUTPUT_DIR/file_analysis/suid_sgid_files.txt"
    
    # Buscar arquivos ocultos
    find / -name ".*" -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -la {} \; 2>/dev/null > "$OUTPUT_DIR/file_analysis/hidden_files.txt"
    
    echo -e "${BLUE}[*] Resultados da análise de arquivos em $OUTPUT_DIR/file_analysis/${NC}"
}

# Função para gerar hash dos arquivos importantes
hash_files() {
    echo -e "${GREEN}[+] Gerando hashes de arquivos importantes...${NC}"
    
    # Lista de arquivos importantes para hash
    IMPORTANT_FILES=(
        /etc/passwd
        /etc/shadow
        /etc/group
        /etc/sudoers
        /etc/ssh/sshd_config
        /etc/hosts
        /etc/crontab
        /etc/resolv.conf
    )
    
    echo "Hashes SHA-256 de arquivos importantes:" > "$OUTPUT_DIR/file_hashes.txt"
    echo "-------------------------------------" >> "$OUTPUT_DIR/file_hashes.txt"
    
    for file in "${IMPORTANT_FILES[@]}"; do
        if [ -f "$file" ]; then
            sha256sum "$file" >> "$OUTPUT_DIR/file_hashes.txt"
        else
            echo "$file - não encontrado" >> "$OUTPUT_DIR/file_hashes.txt"
        fi
    done
    
    echo -e "${BLUE}[*] Hashes salvos em $OUTPUT_DIR/file_hashes.txt${NC}"
}

# Função para gerar relatório completo
full_analysis() {
    echo -e "${YELLOW}[*] Iniciando análise forense completa...${NC}"
    system_info
    process_analysis
    network_analysis
    log_analysis
    user_analysis
    cron_analysis
    service_analysis
    file_analysis
    hash_files
    echo -e "${GREEN}[+] Análise completa concluída!${NC}"
    echo -e "${YELLOW}[*] Todos os resultados foram salvos em $OUTPUT_DIR/${NC}"
}

# Menu interativo
show_menu() {
    clear
    echo -e "${RED}============================================${NC}"
    echo -e "${RED}       Forensic Explorer - Versão 1.0        ${NC}"
    echo -e "${RED}============================================${NC}"
    echo -e "${GREEN} 1. Informações do sistema${NC}"
    echo -e "${GREEN} 2. Análise de processos${NC}"
    echo -e "${GREEN} 3. Análise de rede${NC}"
    echo -e "${GREEN} 4. Análise de logs${NC}"
    echo -e "${GREEN} 5. Análise de usuários${NC}"
    echo -e "${GREEN} 6. Análise de tarefas agendadas${NC}"
    echo -e "${GREEN} 7. Análise de serviços${NC}"
    echo -e "${GREEN} 8. Análise de arquivos${NC}"
    echo -e "${GREEN} 9. Gerar hashes de arquivos${NC}"
    echo -e "${YELLOW}10. Análise completa${NC}"
    echo -e "${RED} 0. Sair${NC}"
    echo -e "${RED}============================================${NC}"
}

# Loop do menu
while true; do
    show_menu
    read -p "Selecione uma opção [0-10]: " option
    case $option in
        1) system_info ;;
        2) process_analysis ;;
        3) network_analysis ;;
        4) log_analysis ;;
        5) user_analysis ;;
        6) cron_analysis ;;
        7) service_analysis ;;
        8) file_analysis ;;
        9) hash_files ;;
        10) full_analysis ;;
        0) 
            echo -e "${RED}[*] Saindo do Forensic Explorer...${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}[ERRO] Opção inválida!${NC}"
            ;;
    esac
    read -p "Pressione [Enter] para continuar..."
done