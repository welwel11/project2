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
export IP=$( curl -sS icanhazip.com )

clear && clear && clear

echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  » This Will Quick Setup VPN Server On Your Server"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
sleep 2

# Cek Arsitektur
if [[ $( uname -m ) == "x86_64" ]]; then
    echo -e "${OK} Your Architecture Is Supported ( ${green}$( uname -m )${NC} )"
else
    echo -e "${ERROR} Your Architecture Is Not Supported ( ${YELLOW}$( uname -m )${NC} )"
    exit 1
fi

# Cek OS
OS_ID=$(grep -w ID /etc/os-release | head -n1 | cut -d= -f2 | tr -d '"')
OS_NAME=$(grep -w PRETTY_NAME /etc/os-release | head -n1 | cut -d= -f2 | tr -d '"')

if [[ "$OS_ID" == "ubuntu" || "$OS_ID" == "debian" ]]; then
    echo -e "${OK} Your OS Is Supported ( ${green}$OS_NAME${NC} )"
else
    echo -e "${ERROR} Your OS Is Not Supported ( ${YELLOW}$OS_NAME${NC} )"
    exit 1
fi

# IP Address
if [[ $IP == "" ]]; then
    echo -e "${ERROR} IP Address ( ${YELLOW}Not Detected${NC} )"
else
    echo -e "${OK} IP Address ( ${green}$IP${NC} )"
fi

echo ""
read -p "$( echo -e "Press ${GRAY}[ ${NC}${green}Enter${NC} ${GRAY}]${NC} For Starting Installation") "
clear

if [ "${EUID}" -ne 0 ]; then
    echo "You need to run this script as root"
    exit 1
fi

if [ "$(systemd-detect-virt)" == "openvz" ]; then
    echo "OpenVZ is not supported"
    exit 1
fi

# Instal Ruby & Wondershaper
apt install ruby -y
gem install lolcat
apt install wondershaper -y
clear

REPO="https://raw.githubusercontent.com/welwel11/project2/main/"

start=$(date +%s)
secs_to_human() {
    echo "Installation time : $((${1} / 3600)) hours $(((${1} / 60) % 60)) minute's $((${1} % 60)) seconds"
}

# Fungsi Status
function print_ok() { echo -e "${OK} ${BLUE} $1 ${FONT}"; }
function print_install() {
    echo -e "${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}"
    echo -e "${YELLOW} » $1 ${FONT}"
    echo -e "${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}"
    sleep 1
}
function print_error() { echo -e "${ERROR} ${REDBG} $1 ${FONT}"; }
function print_success() { if [[ 0 -eq $? ]]; then echo -e "${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}"; echo -e "${Green} » $1 berhasil dipasang"; echo -e "${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}"; sleep 2; fi; }

# Cek root
function is_root() { [[ 0 == "$UID" ]] && print_ok "Root user Start installation process" || print_error "Current user is not root"; }

# Buat direktori xray
print_install "Membuat direktori xray"
mkdir -p /etc/xray /var/log/xray /var/lib/kyt >/dev/null 2>&1
touch /etc/xray/domain /var/log/xray/access.log /var/log/xray/error.log

# Ambil RAM Info
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
export OS_Name=$OS_NAME
export Kernel=$(uname -r)
export Arch=$(uname -m)
export IP=$(curl -s https://ipinfo.io/ip/)

# Fungsi Setup Awal
function first_setup() {
    timedatectl set-timezone Asia/Jakarta
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
    print_success "Directory Xray"

    if [[ "$OS_ID" == "ubuntu" ]]; then
        echo "Setup Dependencies $OS_NAME"
        sudo apt update -y
        apt-get install --no-install-recommends software-properties-common -y
        add-apt-repository ppa:vbernat/haproxy-3.0 -y
        apt-get -y install haproxy=3.0.*
    else
        echo "Setup Dependencies For OS $OS_NAME"
        curl https://haproxy.debian.net/bernat.debian.org.gpg | gpg --dearmor >/usr/share/keyrings/haproxy.debian.net.gpg
        echo deb "[signed-by=/usr/share/keyrings/haproxy.debian.net.gpg]" http://haproxy.debian.net Bullseye-2.6 main >/etc/apt/sources.list.d/haproxy.list
        sudo apt-get update
        apt-get -y install haproxy=2.6.*
    fi
}

# ... [Fungsi lainnya seperti nginx_install, base_package, pasang_domain, pasang_ssl, install_xray, ssh, udp_mini, ssh_slow, ins_SSHD, ins_dropbear, ins_vnstat, ins_backup, ins_swab, ins_Fail2ban, ins_epro, ins_restart, menu, profile, enable_services] ...

# Instalasi Utama
function instal() {
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

history -c
rm -rf /root/menu /root/*.zip /root/*.sh /root/LICENSE /root/README.md /root/domain
secs_to_human "$(($(date +%s) - ${start}))"
echo -e "${green} Script Successfull Installed"
read -p "$( echo -e "Press ${YELLOW}[ ${NC}${YELLOW}Enter${NC} ${YELLOW}]${NC} For reboot") "
reboot
