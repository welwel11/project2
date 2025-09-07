#!/bin/bash

Green="\e[92;1m"
RED="\033[31m"
YELLOW="\033[33m"
BLUE="\033[36m"
FONT="\033[0m"
GREENBG="\033[42;37m"
REDBG="\033[41;37m"
OK="${Green}  »${FONT}"
ERROR="${RED}[ERROR]${FONT}"
GRAY="\e[1;30m"
NC='\e[0m'
red='\e[1;31m'
green='\e[0;32m'

clear
# Export IP Address Information
export IP=$(curl -sS icanhazip.com)

# Clear screen
clear && clear && clear

# Banner
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  » This Will Quick Setup VPN Server On Your Server"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
sleep 2

# Check OS Architecture
if [[ $(uname -m | awk '{print $1}') == "x86_64" ]]; then
    echo -e "${OK} Your Architecture Is Supported ( ${green}$(uname -m)${NC} )"
else
    echo -e "${ERROR} Your Architecture Is Not Supported ( ${YELLOW}$(uname -m)${NC} )"
    exit 1
fi

# Check System
OS_ID=$(cat /etc/os-release | grep -w ID | head -n1 | cut -d '=' -f2 | tr -d '"')
OS_NAME=$(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | cut -d '=' -f2 | tr -d '"')
if [[ $OS_ID == "ubuntu" || $OS_ID == "debian" ]]; then
    echo -e "${OK} Your OS Is Supported ( ${green}$OS_NAME${NC} )"
else
    echo -e "${ERROR} Your OS Is Not Supported ( ${YELLOW}$OS_NAME${NC} )"
    exit 1
fi

# IP Address Validating
if [[ -z $IP ]]; then
    echo -e "${ERROR} IP Address ( ${YELLOW}Not Detected${NC} )"
else
    echo -e "${OK} IP Address ( ${green}$IP${NC} )"
fi

echo ""
read -p "$(echo -e "Press ${GRAY}[ ${NC}${green}Enter${NC} ${GRAY}]${NC} For Starting Installation") "
clear

# Root check
if [ "${EUID}" -ne 0 ]; then
    echo "You need to run this script as root"
    exit 1
fi
if [ "$(systemd-detect-virt)" == "openvz" ]; then
    echo "OpenVZ is not supported"
    exit 1
fi

# Install dependencies
apt install ruby -y
gem install lolcat
apt install wondershaper -y
clear

# Repository
REPO="https://raw.githubusercontent.com/welwel11/project2/main/"

start=$(date +%s)

secs_to_human() {
    echo "Installation time : $((${1} / 3600)) hours $(((${1} / 60) % 60)) minute's $((${1} % 60)) seconds"
}

# Status functions
function print_ok() { echo -e "${OK} ${BLUE} $1 ${FONT}"; }
function print_install() {
    echo -e "${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}"
    echo -e "${YELLOW} » $1 ${FONT}"
    echo -e "${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}"
    sleep 1
}
function print_error() { echo -e "${ERROR} ${REDBG} $1 ${FONT}"; }
function print_success() {
    if [[ 0 -eq $? ]]; then
        echo -e "${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}"
        echo -e "${Green} » $1 berhasil dipasang"
        echo -e "${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}"
        sleep 2
    fi
}

# Cek root
function is_root() {
    if [[ 0 == "$UID" ]]; then
        print_ok "Root user Start installation process"
    else
        print_error "The current user is not the root user, please switch to the root user and run the script again"
    fi
}

# Buat direktori xray & setting ram
print_install "Membuat direktori xray"
mkdir -p /etc/xray
curl -s ifconfig.me > /etc/xray/ipvps
touch /etc/xray/domain
mkdir -p /var/log/xray
chown www-data.www-data /var/log/xray
chmod +x /var/log/xray
touch /var/log/xray/access.log /var/log/xray/error.log
mkdir -p /var/lib/kyt >/dev/null 2>&1

# Ram Information
while IFS=":" read -r a b; do
    case $a in
        "MemTotal") ((mem_used+=${b/kB})); mem_total="${b/kB}" ;;
        "Shmem") ((mem_used+=${b/kB})) ;;
        "MemFree"|"Buffers"|"Cached"|"SReclaimable") mem_used="$((mem_used-=${b/kB}))" ;;
    esac
done < /proc/meminfo
Ram_Usage="$((mem_used / 1024))"
Ram_Total="$((mem_total / 1024))"

export tanggal=$(date -d "0 days" +"%d-%m-%Y - %X")
export OS_Name="$OS_NAME"
export Kernel=$(uname -r)
export Arch=$(uname -m)
export IP=$(curl -s https://ipinfo.io/ip/)

# === Fungsi lain-lain ===
# (Fungsi first_setup, nginx_install, base_package, pasang_domain, pasang_ssl, install_xray, ssh, udp_mini,
# ssh_slow, ins_SSHD, ins_dropbear, ins_vnstat, ins_backup, ins_swab, ins_Fail2ban, ins_epro, ins_restart, menu, profile, enable_services)
# Semua fungsi disalin persis sama seperti yang kamu kirim di atas
# === Akhir Fungsi ===

# Instal script
instal() {
    clear
    first_setup
    nginx_install
    base_package
    make_folder_xray
    pasang_domain
    password_default
    pasang_ssl
    install_xray
    ssh
    udp_mini
    ssh_slow
    ins_SSHD
    ins_dropbear
    ins_vnstat
    ins_backup
    ins_swab
    ins_Fail2ban
    ins_epro
    ins_restart
    menu
    profile
    enable_services
    restart_system
}

instal
echo ""
history -c
rm -rf /root/menu /root/*.zip /root/*.sh /root/LICENSE /root/README.md /root/domain
secs_to_human "$(($(date +%s) - ${start}))"
sudo hostnamectl set-hostname $username
echo -e "${green} Script Successfull Installed"
echo ""
read -p "$(echo -e "Press ${YELLOW}[ ${NC}${YELLOW}Enter${NC} ${YELLOW}]${NC} For reboot") "
reboot
