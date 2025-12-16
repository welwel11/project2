#!/bin/bash

# ================== WARNA ==================
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

# ================== AMBIL IP (FIX UBUNTU 24) ==================
# FIX: icanhazip.com kadang timeout → fallback
export IP=$(curl -sS --max-time 5 https://ipv4.icanhazip.com || curl -sS --max-time 5 https://ifconfig.me)

clear

# ================== BANNER ==================
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  » This Will Quick Setup VPN Server On Your Server"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
sleep 2

# ================== CEK ARSITEKTUR ==================
ARCH=$(uname -m)
if [[ "$ARCH" == "x86_64" ]]; then
    echo -e "${OK} Architecture Supported (${green}${ARCH}${NC})"
else
    echo -e "${ERROR} Architecture Not Supported (${YELLOW}${ARCH}${NC})"
    exit 1
fi

# ================== CEK OS (UBUNTU 24 FIX) ==================
OS_ID=$(grep -w ID /etc/os-release | cut -d= -f2 | tr -d '"')
OS_NAME=$(grep -w PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')

if [[ "$OS_ID" == "ubuntu" || "$OS_ID" == "debian" ]]; then
    echo -e "${OK} OS Supported (${green}${OS_NAME}${NC})"
else
    echo -e "${ERROR} OS Not Supported (${YELLOW}${OS_NAME}${NC})"
    exit 1
fi

# ================== VALIDASI IP ==================
if [[ -z "$IP" ]]; then
    echo -e "${ERROR} IP Address ( ${YELLOW}Not Detected${NC} )"
    exit 1
else
    echo -e "${OK} IP Address ( ${green}${IP}${NC} )"
fi

# ================== KONFIRMASI ==================
echo ""
read -rp "Press [ ENTER ] For Starting Installation "
echo ""
clear

# ================== CEK ROOT ==================
if [[ "$EUID" -ne 0 ]]; then
    echo "You need to run this script as root"
    exit 1
fi

# ================== CEK VIRTUALISASI ==================
# FIX: Ubuntu 24 masih support systemd-detect-virt
if [[ "$(systemd-detect-virt)" == "openvz" ]]; then
    echo "OpenVZ is not supported"
    exit 1
fi

# ================== IZIN SCRIPT (TETAP ADA) ==================
MYIP=$(curl -sS --max-time 5 https://ipv4.icanhazip.com)
echo -e "\e[32mloading...\e[0m"
clear

# ================== REPO ==================
REPO="https://raw.githubusercontent.com/welwel11/project2/main/"

# ================== TIMER ==================
start=$(date +%s)
secs_to_human() {
    echo "Installation time : $((${1} / 3600)) hours $(((${1} / 60) % 60)) minute(s) $((${1} % 60)) seconds"
}

# ================== STATUS FUNCTION ==================
print_ok() {
    echo -e "${OK} ${BLUE}$1${FONT}"
}

print_install() {
    echo -e "${green}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${FONT}"
    echo -e "${YELLOW} » $1 ${FONT}"
    echo -e "${green}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${FONT}"
    sleep 1
}

print_error() {
    echo -e "${ERROR} ${REDBG} $1 ${FONT}"
}

print_success() {
    if [[ $? -eq 0 ]]; then
        echo -e "${green}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${FONT}"
        echo -e "${Green} » $1 berhasil dipasang${FONT}"
        echo -e "${green}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${FONT}"
        sleep 1
    fi
}

# ================== CEK ROOT FUNCTION ==================
is_root() {
    if [[ "$UID" -eq 0 ]]; then
        print_ok "Root user detected"
    else
        print_error "Please run this script as root"
        exit 1
    fi
}

# = BUAT DIREKTORI XRAY =
print_install "Membuat direktori xray"

# Direktori utama xray
mkdir -p /etc/xray

# Simpan IP VPS (FIX: curl lebih stabil)
curl -sS --max-time 5 https://ifconfig.me > /etc/xray/ipvps

# File domain (kosong, aman)
touch /etc/xray/domain

# Direktori log xray
mkdir -p /var/log/xray

# FIX UBUNTU 24: owner www-data:www-data (bukan titik)
chown www-data:www-data /var/log/xray
chmod 755 /var/log/xray

# File log
touch /var/log/xray/access.log
touch /var/log/xray/error.log

# Direktori tambahan (tetap 1:1)
mkdir -p /var/lib/kyt >/dev/null 2>&1

# = RAM INFORMATION =
mem_used=0
mem_total=0

while IFS=":" read -r a b; do
    case "$a" in
        "MemTotal")
            mem_total="${b/kB}"
            mem_used="${b/kB}"
        ;;
        "Shmem")
            mem_used=$((mem_used + ${b/kB}))
        ;;
        "MemFree" | "Buffers" | "Cached" | "SReclaimable")
            mem_used=$((mem_used - ${b/kB}))
        ;;
    esac
done < /proc/meminfo

Ram_Usage="$((mem_used / 1024))"
Ram_Total="$((mem_total / 1024))"

# = INFORMASI SISTEM =
export tanggal="$(date +"%d-%m-%Y - %T")"

# FIX UBUNTU 24: parsing PRETTY_NAME lebih aman
export OS_Name="$(grep -w PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')"

export Kernel="$(uname -r)"
export Arch="$(uname -m)"

# FIX: ipinfo kadang rate limit → fallback aman
export IP="$(curl -sS --max-time 5 https://ipinfo.io/ip || curl -sS --max-time 5 https://ipv4.icanhazip.com)"

# ================== CHANGE ENVIRONMENT SYSTEM ==================
function first_setup() {

    # Timezone
    timedatectl set-timezone Asia/Jakarta

    print_install "Disable IPv6 Permanen"

    # ================== SYSCTL DISABLE IPV6 ==================
    cat >/etc/sysctl.d/99-disable-ipv6.conf <<EOF
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF

    # Apply sysctl langsung
    sysctl --system >/dev/null 2>&1

# ================== SYSTEMD SERVICE ==================
    cat >/etc/systemd/system/disable-ipv6.service <<'EOF'
[Unit]
Description=Disable IPv6 Permanently
After=network.target

[Service]
Type=oneshot
ExecStart=/sbin/sysctl -p /etc/sysctl.d/99-disable-ipv6.conf
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable disable-ipv6.service >/dev/null 2>&1
    systemctl start disable-ipv6.service  >/dev/null 2>&1

    print_success "IPv6 Disabled Permanently"

    # ================== IPTABLES-PERSISTENT ==================
    # FIX UBUNTU 24: non-interactive
    echo iptables-persistent iptables-persistent/autosave_v6 boolean false | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true  | debconf-set-selections

    # ================== INSTALL HAPROXY ==================
    OS_ID=$(grep -w ID /etc/os-release | cut -d= -f2 | tr -d '"')

    if [[ "$OS_ID" == "ubuntu" ]]; then
        apt update -y
        # Ubuntu 24 sudah menyediakan haproxy terbaru
        apt install -y software-properties-common haproxy
    elif [[ "$OS_ID" == "debian" ]]; then
        curl -fsSL https://haproxy.debian.net/bernat.debian.org.gpg \
            | gpg --dearmor \
            -o /usr/share/keyrings/haproxy.debian.net.gpg

        echo "deb [signed-by=/usr/share/keyrings/haproxy.debian.net.gpg] \
http://haproxy.debian.net bullseye-2.2 main" \
            >/etc/apt/sources.list.d/haproxy.list

        apt update -y
        apt install -y haproxy
    fi
}

# ================== GEO PROJECT ==================
clear

function nginx_install() {

    # Deteksi OS
    OS_ID=$(grep -w ID /etc/os-release | cut -d= -f2 | tr -d '"')
    OS_NAME=$(grep -w PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')

    if [[ "$OS_ID" == "ubuntu" ]]; then
        print_install "Setup nginx For OS Is $OS_NAME"
        # Ubuntu 24: nginx dari repo resmi
        apt update -y
        apt install -y nginx

    elif [[ "$OS_ID" == "debian" ]]; then
        print_install "Setup nginx For OS Is $OS_NAME"
        apt update -y
        apt install -y nginx

    else
        echo -e " Your OS Is Not Supported ( ${YELLOW}${OS_NAME}${FONT} )"
        # exit 1 (tetap dikomentari, 1:1)
    fi
}

# ================== UPDATE & INSTALL BASE PACKAGE ==================
function base_package() {
    clear
    print_install "Menginstall Packet Yang Dibutuhkan"

    # Update repository
    apt update -y

    # Install paket utama (1:1)
    apt install -y \
        zip pwgen openssl netcat socat cron bash-completion figlet sudo \
        debconf-utils speedtest-cli vnstat net-tools iptables \
        iptables-persistent netfilter-persistent curl wget jq \
        build-essential gcc g++ make cmake git screen socat xz-utils \
        apt-transport-https dnsutils chrony openvpn easy-rsa

    # Upgrade system
    apt upgrade -y
    apt dist-upgrade -y

    # ================== WAKTU & NTP ==================
    # Ubuntu 24 default chrony
    systemctl enable --now chrony >/dev/null 2>&1

    # ntpdate tidak default di Ubuntu 24 → fallback aman
    if command -v ntpdate >/dev/null 2>&1; then
        ntpdate pool.ntp.org
    fi

    # ================== MATIKAN FIREWALL BAWAAN ==================
    # (JANGAN DIHAPUS – sesuai request)
    systemctl disable --now ufw 2>/dev/null
    systemctl disable --now firewalld 2>/dev/null

    # ================== HAPUS MAIL SERVER ==================
    apt-get remove --purge exim4 -y >/dev/null 2>&1

    # ================== IPTABLES-PERSISTENT ==================
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections

    # ================== CLEAN SYSTEM ==================
    apt-get clean
    apt-get autoremove -y

    print_success "Packet Yang Dibutuhkan"
}

# ================== SECURITY HARDENING ==================
function security_hardening() {
    clear
    print_install "Security Hardening"

    # MaxAuthTries
    if grep -q "^#\?MaxAuthTries" /etc/ssh/sshd_config; then
        sed -i 's/^#\?MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config
    else
        echo "MaxAuthTries 3" >> /etc/ssh/sshd_config
    fi

    # LoginGraceTime
    if grep -q "^#\?LoginGraceTime" /etc/ssh/sshd_config; then
        sed -i 's/^#\?LoginGraceTime.*/LoginGraceTime 30/' /etc/ssh/sshd_config
    else
        echo "LoginGraceTime 30" >> /etc/ssh/sshd_config
    fi

    # Restart SSH (Ubuntu 24 pakai ssh)
    systemctl restart ssh

    print_success "Security Hardening"
}

# ================== FIREWALL HARDENING ==================
function firewall_setup() {
    clear
    print_install "Firewall Hardening (iptables)"

    # Flush rule lama
    iptables -F
    iptables -X

    # Default policy
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT

    # ================== BASIC RULE ==================
    # Loopback
    iptables -A INPUT -i lo -j ACCEPT

    # Established & Related
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # Drop invalid packet
    iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

    # ================== SSH PROTECTION ==================
    # Limit koneksi SSH (bruteforce)
    iptables -A INPUT -p tcp --dport 22 -m connlimit --connlimit-above 3 -j DROP
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT

    # ================== WEB ==================
    iptables -A INPUT -p tcp --dport 80 -j ACCEPT
    iptables -A INPUT -p tcp --dport 443 -j ACCEPT

    # ================== SYN FLOOD PROTECTION ==================
    iptables -A INPUT -p tcp --syn -m limit --limit 2/second --limit-burst 10 -j ACCEPT

    # ================== SAVE RULE ==================
    # Ubuntu 24: netfilter-persistent masih valid
    iptables-save > /etc/iptables.up.rules

    netfilter-persistent save >/dev/null 2>&1
    netfilter-persistent reload >/dev/null 2>&1

    print_success "Firewall Active"
}

clear
# ================== SETUP DOMAIN ==================
function pasang_domain() {
    echo ""
    clear
    echo -e "${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}"
    echo -e "${YELLOW}» SETUP DOMAIN CLOUDFLARE ${FONT}"
    echo -e "${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}"
    echo -e "  [1] Domain Pribadi"
    echo -e "  [2] Domain Bawaan"
    echo -e "${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}"
    read -rp "  Silahkan Pilih Menu Domain 1 or 2 (enter) : " host
    echo ""

    # Pastikan direktori ada
    mkdir -p /var/lib/kyt

    if [[ "$host" == "1" ]]; then
        echo -e "   \e[1;32mMasukan Domain Anda ! ${NC}"
        read -rp "   Subdomain: " host1

        # Simpan konfigurasi (1:1)
        echo "IP=" >> /var/lib/kyt/ipvps.conf
        echo "$host1" > /etc/xray/domain
        echo "$host1" > /root/domain
        echo ""

    elif [[ "$host" == "2" ]]; then
        # Install domain bawaan (Cloudflare)
        wget -q ${REPO}files/cf.sh -O /root/cf.sh
        chmod +x /root/cf.sh
        /root/cf.sh
        rm -f /root/cf.sh
        clear

    else
        print_install "Random Subdomain/Domain is Used"
        clear
    fi
}

# ================== GANTI PASSWORD DEFAULT / FINAL CHECK ==================
function restart_system() {

    clear

    # ================== IZIN SCRIPT ==================
    MYIP=$(curl -sS --max-time 5 https://ipv4.icanhazip.com)
    echo -e "\e[32mloading...\e[0m"
    clear

    izinsc="https://raw.githubusercontent.com/welwel11/izin/main/izin"

    # ================== USERNAME ==================
    rm -f /usr/bin/user

    username=$(curl -sS --max-time 10 "$izinsc" | grep "$MYIP" | awk '{print $2}')
    expx=$(curl -sS --max-time 10 "$izinsc" | grep "$MYIP" | awk '{print $3}')

    echo "$username" > /usr/bin/user
    echo "$expx" > /usr/bin/e

    # ================== DETAIL ORDER ==================
    username=$(cat /usr/bin/user 2>/dev/null)
    oid=$(cat /usr/bin/ver 2>/dev/null)
    exp=$(cat /usr/bin/e 2>/dev/null)

    clear

    # ================== CERTIFICATE STATUS ==================
    # Variabel valid & today diasumsikan sudah ada (1:1)
    d1=$(date -d "$valid" +%s 2>/dev/null)
    d2=$(date -d "$today" +%s 2>/dev/null)

    if [[ -n "$d1" && -n "$d2" ]]; then
        certifacate=$(((d1 - d2) / 86400))
    else
        certifacate="N/A"
    fi

    # ================== VPS INFORMATION ==================
    DATE=$(date +'%Y-%m-%d')

    datediff() {
        d1=$(date -d "$1" +%s)
        d2=$(date -d "$2" +%s)
        echo -e "$COLOR1 $NC Expiry In   : $(( (d1 - d2) / 86400 )) Days"
    }

}

clear
# ================== PASANG SSL ==================
function pasang_ssl() {
    clear
    print_install "Memasang SSL Pada Domain"

    # Hapus cert lama
    rm -f /etc/xray/xray.key
    rm -f /etc/xray/xray.crt

    # Ambil domain
    domain=$(cat /root/domain 2>/dev/null)

    # Cegah domain kosong
    if [[ -z "$domain" ]]; then
        print_error "Domain tidak ditemukan"
        return 1
    fi

    # ================== STOP SERVICE PORT 80 ==================
    STOPWEBSERVER=$(lsof -i:80 -sTCP:LISTEN -P -n | awk 'NR>1 {print $1}' | uniq)

    rm -rf /root/.acme.sh
    mkdir -p /root/.acme.sh

    # Stop service yang pakai port 80
    for svc in $STOPWEBSERVER; do
        systemctl stop "$svc" 2>/dev/null
    done

    # Pastikan nginx berhenti
    systemctl stop nginx 2>/dev/null

    # ================== INSTALL ACME.SH ==================
    curl -s https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
    chmod +x /root/.acme.sh/acme.sh

    /root/.acme.sh/acme.sh --upgrade --auto-upgrade
    /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt

    # ================== ISSUE CERT ==================
    /root/.acme.sh/acme.sh --issue -d "$domain" --standalone -k ec-256

    # ================== INSTALL CERT ==================
    /root/.acme.sh/acme.sh --install-cert -d "$domain" \
        --fullchainpath /etc/xray/xray.crt \
        --keypath /etc/xray/xray.key \
        --ecc

    chmod 600 /etc/xray/xray.key

    print_success "SSL Certificate"
}

# ================== MAKE FOLDER XRAY ==================
function make_folder_xray() {

    # ================== HAPUS DATABASE LAMA ==================
    rm -f /etc/vmess/.vmess.db
    rm -f /etc/vless/.vless.db
    rm -f /etc/trojan/.trojan.db
    rm -f /etc/shadowsocks/.shadowsocks.db
    rm -f /etc/ssh/.ssh.db
    rm -f /etc/bot/.bot.db
    rm -f /etc/user-create/user.log

    # ================== BUAT DIREKTORI ==================
    mkdir -p /etc/bot
    mkdir -p /etc/xray
    mkdir -p /etc/vmess
    mkdir -p /etc/vless
    mkdir -p /etc/trojan
    mkdir -p /etc/shadowsocks
    mkdir -p /etc/ssh
    mkdir -p /usr/bin/xray
    mkdir -p /var/log/xray
    mkdir -p /var/www/html

    mkdir -p /etc/kyt/limit/vmess/ip
    mkdir -p /etc/kyt/limit/vless/ip
    mkdir -p /etc/kyt/limit/trojan/ip
    mkdir -p /etc/kyt/limit/ssh/ip

    mkdir -p /etc/limit/vmess
    mkdir -p /etc/limit/vless
    mkdir -p /etc/limit/trojan
    mkdir -p /etc/limit/ssh

    mkdir -p /etc/user-create

    # ================== PERMISSION ==================
    chmod 755 /var/log/xray

    # ================== FILE DASAR ==================
    touch /etc/xray/domain
    touch /var/log/xray/access.log
    touch /var/log/xray/error.log

    touch /etc/vmess/.vmess.db
    touch /etc/vless/.vless.db
    touch /etc/trojan/.trojan.db
    touch /etc/shadowsocks/.shadowsocks.db
    touch /etc/ssh/.ssh.db
    touch /etc/bot/.bot.db

    # ================== INIT DATABASE ==================
    echo "& plughin Account" >> /etc/vmess/.vmess.db
    echo "& plughin Account" >> /etc/vless/.vless.db
    echo "& plughin Account" >> /etc/trojan/.trojan.db
    echo "& plughin Account" >> /etc/shadowsocks/.shadowsocks.db
    echo "& plughin Account" >> /etc/ssh/.ssh.db

    # ================== USER LOG ==================
    echo "echo -e 'Vps Config User Account'" >> /etc/user-create/user.log
}
#Instal Xray
function install_xray() {
clear
    print_install "Core Xray Latest Version"
    domainSock_dir="/run/xray";! [ -d $domainSock_dir ] && mkdir  $domainSock_dir
    chown www-data.www-data $domainSock_dir
    
    # / / Ambil Xray Core Version Terbaru
latest_version="$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data --version 1.8.24
 
    # // Ambil Config Server
    wget -O /etc/xray/config.json "${REPO}config/config.json" >/dev/null 2>&1
    wget -O /etc/systemd/system/runn.service "${REPO}files/runn.service" >/dev/null 2>&1
    #chmod +x /usr/local/bin/xray
    domain=$(cat /etc/xray/domain)
    IPVS=$(cat /etc/xray/ipvps)
    print_success "Core Xray Latest Version"
    
    # Settings UP Nginix Server
    clear
    curl -s ipinfo.io/city >>/etc/xray/city
    curl -s ipinfo.io/org | cut -d " " -f 2-10 >>/etc/xray/isp
    print_install "Memasang Konfigurasi Packet"
    wget -O /etc/haproxy/haproxy.cfg "${REPO}config/haproxy.cfg" >/dev/null 2>&1
    wget -O /etc/nginx/conf.d/xray.conf "${REPO}config/xray.conf" >/dev/null 2>&1
    sed -i "s/xxx/${domain}/g" /etc/haproxy/haproxy.cfg
    sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/xray.conf
    curl ${REPO}config/nginx.conf > /etc/nginx/nginx.conf
    
cat /etc/xray/xray.crt /etc/xray/xray.key | tee /etc/haproxy/hap.pem

    # > Set Permission
    chmod +x /etc/systemd/system/runn.service

    # > Create Service
    rm -rf /etc/systemd/system/xray.service.d
    cat >/etc/systemd/system/xray.service <<EOF
Description=Xray Service
Documentation=https://github.com
After=network.target nss-lookup.target

[Service]
User=www-data
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target

EOF
print_success "Konfigurasi Packet"
}

function ssh(){
clear
print_install "Memasang Password SSH"

wget -O /etc/pam.d/common-password "${REPO}files/password"
chmod 644 /etc/pam.d/common-password

DEBIAN_FRONTEND=noninteractive dpkg-reconfigure keyboard-configuration

ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime

sed -i 's/^AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config

systemctl restart ssh

print_success "Password SSH"
}

function udp_mini(){
clear
print_install "Memasang Service Limit IP & Quota"
wget -q https://raw.githubusercontent.com/welwel11/project2/main/config/fv-tunnel && chmod +x fv-tunnel && ./fv-tunnel

# // Installing UDP Mini
mkdir -p /usr/local/kyt/
wget -q -O /usr/local/kyt/udp-mini "${REPO}files/udp-mini"
chmod +x /usr/local/kyt/udp-mini
wget -q -O /etc/systemd/system/udp-mini-1.service "${REPO}files/udp-mini-1.service"
wget -q -O /etc/systemd/system/udp-mini-2.service "${REPO}files/udp-mini-2.service"
wget -q -O /etc/systemd/system/udp-mini-3.service "${REPO}files/udp-mini-3.service"
systemctl disable udp-mini-1
systemctl stop udp-mini-1
systemctl enable udp-mini-1
systemctl start udp-mini-1
systemctl disable udp-mini-2
systemctl stop udp-mini-2
systemctl enable udp-mini-2
systemctl start udp-mini-2
systemctl disable udp-mini-3
systemctl stop udp-mini-3
systemctl enable udp-mini-3
systemctl start udp-mini-3
print_success "Limit IP Service"
}

function ssh_slow(){
clear
# // Installing UDP Mini
print_install "Memasang modul SlowDNS Server"
    wget -q -O /tmp/nameserver "${REPO}files/nameserver" >/dev/null 2>&1
    chmod +x /tmp/nameserver
    bash /tmp/nameserver | tee /root/install.log
 print_success "SlowDNS"
}

clear
function ins_SSHD(){
clear
print_install "Memasang SSHD"
wget -q -O /etc/ssh/sshd_config "${REPO}files/sshd" >/dev/null 2>&1
chmod 700 /etc/ssh/sshd_config
/etc/init.d/ssh restart
systemctl restart ssh
/etc/init.d/ssh status
print_success "SSHD"
}

clear
function ins_SSHD(){
clear
print_install "Memasang SSHD"

# Download konfigurasi SSH
wget -q -O /etc/ssh/sshd_config "${REPO}files/sshd"

# Permission yang BENAR untuk Ubuntu 24
chmod 600 /etc/ssh/sshd_config
chown root:root /etc/ssh/sshd_config

# Reload & restart SSH (systemd native)
systemctl daemon-reexec
systemctl restart ssh
systemctl status ssh --no-pager

print_success "SSHD"
}

clear
function ins_vnstat(){
clear
print_install "Menginstall Vnstat"

# Install vnstat dari repository resmi Ubuntu 24
apt update -y
apt install -y vnstat sqlite3

# Detect interface otomatis (Ubuntu 24 pakai ens*, eth*, enp*)
NET=$(ip route get 1.1.1.1 | awk '{print $5; exit}')

# Update database vnstat
vnstat --add -i $NET >/dev/null 2>&1
vnstat -u -i $NET >/dev/null 2>&1

# Set interface di config
sed -i "s/^Interface.*/Interface \"$NET\"/g" /etc/vnstat.conf

# Permission database
chown -R vnstat:vnstat /var/lib/vnstat

# Enable & restart service (systemd)
systemctl daemon-reexec
systemctl enable vnstat
systemctl restart vnstat
systemctl status vnstat --no-pager

print_success "Vnstat"
}

function ins_openvpn(){
clear
print_install "Menginstall OpenVPN"

# Download & jalankan installer OpenVPN
wget -q -O /root/openvpn "${REPO}files/openvpn"
chmod +x /root/openvpn
bash /root/openvpn

# Reload systemd
systemctl daemon-reexec

# Enable & restart OpenVPN (support multiple config)
systemctl enable openvpn
systemctl restart openvpn || true

# Fallback jika pakai instance config
systemctl restart openvpn@server 2>/dev/null || true
systemctl restart openvpn@openvpn 2>/dev/null || true

systemctl status openvpn --no-pager 2>/dev/null || true

print_success "OpenVPN"
}

function ins_backup(){
clear
print_install "Memasang Backup Server"

# ===================== RCLONE =====================
apt update -y
apt install -y rclone

# Init rclone (auto quit)
printf "q\n" | rclone config >/dev/null 2>&1

# Ambil config rclone
mkdir -p /root/.config/rclone
wget -q -O /root/.config/rclone/rclone.conf "${REPO}config/rclone.conf"
chmod 600 /root/.config/rclone/rclone.conf

# ===================== WONDERSHAPER =====================
apt install -y git make

cd /tmp
rm -rf wondershaper
git clone https://github.com/magnific0/wondershaper.git
cd wondershaper
make install
cd
rm -rf /tmp/wondershaper

# File limit placeholder
touch /home/limit

# ===================== EMAIL NOTIFICATION =====================
apt install -y msmtp-mta ca-certificates bsd-mailx

cat >/etc/msmtprc <<EOF
defaults
tls on
tls_starttls on
tls_trust_file /etc/ssl/certs/ca-certificates.crt

account default
host smtp.gmail.com
port 587
auth on
user oceantestdigital@gmail.com
from oceantestdigital@gmail.com
password jokerman77
logfile /var/log/msmtp.log
EOF

chmod 600 /etc/msmtprc
chown root:root /etc/msmtprc

print_success "Backup Server"
}

clear
function ins_swab(){
clear
print_install "Memasang Swap 1 G"

# ===================== GOTOP =====================
apt update -y
apt install -y curl wget chrony

gotop_latest="$(curl -s https://api.github.com/repos/xxxserxxx/gotop/releases \
| grep tag_name | sed -E 's/.*"v([^"]+)".*/\1/' | head -n 1)"

gotop_link="https://github.com/xxxserxxx/gotop/releases/download/v${gotop_latest}/gotop_v${gotop_latest}_linux_amd64.deb"

curl -sL "$gotop_link" -o /tmp/gotop.deb
dpkg -i /tmp/gotop.deb >/dev/null 2>&1 || apt -f install -y
rm -f /tmp/gotop.deb

# ===================== SWAP 1 GB =====================
if ! swapon --show | grep -q "/swapfile"; then
    dd if=/dev/zero of=/swapfile bs=1M count=1024 status=none
    chmod 600 /swapfile
    chown root:root /swapfile
    mkswap /swapfile >/dev/null 2>&1
    swapon /swapfile
    echo "/swapfile swap swap defaults 0 0" >> /etc/fstab
fi

# ===================== SYNC WAKTU =====================
systemctl enable --now chrony
chronyc tracking >/dev/null 2>&1

# ===================== TCP BBR =====================
wget -q -O /root/bbr.sh "${REPO}files/bbr.sh"
chmod +x /root/bbr.sh
bash /root/bbr.sh

print_success "Swap 1 G"
}

function ins_Fail2ban(){
clear
print_install "Menginstall Fail2ban"

# ===================== FAIL2BAN =====================
apt update -y
apt install -y fail2ban

systemctl daemon-reexec
systemctl enable --now fail2ban
systemctl restart fail2ban
systemctl status fail2ban --no-pager

# ===================== BANNER SSH =====================
# Download banner
wget -q -O /etc/kyt.txt "${REPO}files/issue.net"
chmod 644 /etc/kyt.txt

# Set banner SSH (hindari duplicate)
sed -i '/^Banner/d' /etc/ssh/sshd_config
echo "Banner /etc/kyt.txt" >> /etc/ssh/sshd_config

# ===================== BANNER DROPBEAR =====================
if [ -f /etc/default/dropbear ]; then
    sed -i 's@^DROPBEAR_BANNER=.*@DROPBEAR_BANNER="/etc/kyt.txt"@' /etc/default/dropbear
fi

# Restart service terkait
systemctl restart ssh 2>/dev/null || true
systemctl restart dropbear 2>/dev/null || true

print_success "Fail2ban"
}

function ins_epro(){
clear
print_install "Menginstall ePro WebSocket Proxy"

# ===================== FILE WS =====================
mkdir -p /usr/local/share/xray

wget -q -O /usr/bin/ws "${REPO}files/ws"
wget -q -O /usr/bin/tun.conf "${REPO}config/tun.conf"
wget -q -O /etc/systemd/system/ws.service "${REPO}files/ws.service"

chmod +x /usr/bin/ws
chmod 644 /usr/bin/tun.conf
chmod 644 /etc/systemd/system/ws.service

# ===================== SYSTEMD =====================
systemctl daemon-reexec
systemctl daemon-reload
systemctl enable ws
systemctl restart ws
systemctl status ws --no-pager

# ===================== GEO DATABASE =====================
wget -q -O /usr/local/share/xray/geosite.dat \
https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat

wget -q -O /usr/local/share/xray/geoip.dat \
https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat

# ===================== TOOL =====================
wget -q -O /usr/sbin/ftvpn "${REPO}files/ftvpn"
chmod +x /usr/sbin/ftvpn

# ===================== CLEAN =====================
apt autoclean -y >/dev/null 2>&1
apt autoremove -y >/dev/null 2>&1

print_success "ePro WebSocket Proxy"
}

function ins_restart(){
clear
print_install "Restarting All Packet"

# ===================== RELOAD SYSTEMD =====================
systemctl daemon-reexec
systemctl daemon-reload

# ===================== RESTART SERVICE =====================
for svc in nginx ssh dropbear fail2ban vnstat haproxy cron ws xray; do
    systemctl restart $svc 2>/dev/null || true
done

# ===================== ENABLE SERVICE =====================
for svc in nginx xray dropbear cron haproxy ws fail2ban vnstat; do
    systemctl enable $svc 2>/dev/null || true
done

# ===================== CLEAR HISTORY =====================
history -c
sed -i '/unset HISTFILE/d' /etc/profile
echo "unset HISTFILE" >> /etc/profile

# ===================== CLEAN CERT =====================
rm -f /root/key.pem /root/cert.pem

print_success "All Packet"
}

#Instal Menu
function menu(){
clear
print_install "Memasang Menu Packet"

# Pastikan unzip tersedia
apt update -y
apt install -y unzip

# Download menu
cd /tmp
rm -rf menu menu.zip
wget -q -O menu.zip "${REPO}menu/menu.zip"

# Extract
unzip -o menu.zip >/dev/null 2>&1

# Permission & install
chmod +x menu/*
mv menu/* /usr/local/sbin/

# Cleanup
rm -rf /tmp/menu /tmp/menu.zip

print_success "Menu Packet"
}

# Membaut Default Menu 
function profile(){
clear

# ===== .profile =====
cat >/root/.profile <<'EOF'
# ~/.profile: executed by Bourne-compatible login shells.
if [ "$BASH" ]; then
    if [ -f ~/.bashrc ]; then
        . ~/.bashrc
    fi
fi
mesg n || true
menu
EOF
chmod 644 /root/.profile

# ===== CRON JOBS =====
cat >/etc/cron.d/xp_all <<'EOF'
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
2 0 * * * root /usr/local/sbin/xp
EOF

cat >/etc/cron.d/logclean <<'EOF'
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/20 * * * * root /usr/local/sbin/clearlog
EOF

cat >/etc/cron.d/daily_reboot <<'EOF'
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 3 * * * root /sbin/reboot
EOF

cat >/etc/cron.d/limit_ip <<'EOF'
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/2 * * * * root /usr/local/sbin/limit-ip
EOF

cat >/etc/cron.d/limit_ip2 <<'EOF'
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/2 * * * * root /usr/bin/limit-ip
EOF

# ===== LOG ROTATE (AMAN) =====
cat >/etc/cron.d/log.nginx <<'EOF'
*/10 * * * * root /usr/bin/truncate -s 0 /var/log/nginx/access.log
EOF

cat >/etc/cron.d/log.xray <<'EOF'
*/10 * * * * root /usr/bin/truncate -s 0 /var/log/xray/access.log
EOF

# Restart cron (systemd Ubuntu 24)
systemctl restart cron
systemctl enable cron >/dev/null 2>&1

# ===== DAILY REBOOT FLAG =====
echo "5" >/home/daily_reboot

# ===== rc-local compatibility Ubuntu 24 =====
cat >/etc/systemd/system/rc-local.service <<'EOF'
[Unit]
Description=/etc/rc.local Compatibility
ConditionPathExists=/etc/rc.local

[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

# shell deny list
grep -qxF "/bin/false" /etc/shells || echo "/bin/false" >> /etc/shells
grep -qxF "/usr/sbin/nologin" /etc/shells || echo "/usr/sbin/nologin" >> /etc/shells

# rc.local
cat >/etc/rc.local <<'EOF'
#!/bin/sh -e
# rc.local - SAFE

echo 1 > /proc/sys/net/ipv4/ip_forward
echo 1 > /proc/sys/net/ipv4/tcp_syncookies

exit 0
EOF

chmod +x /etc/rc.local
systemctl daemon-reload
systemctl enable rc-local >/dev/null 2>&1
systemctl start rc-local >/dev/null 2>&1

# ===== TIME CHECK (tetap 1:1) =====
AUTOREB=$(cat /home/daily_reboot)
SETT=11
if [ "$AUTOREB" -gt "$SETT" ]; then
    TIME_DATE="PM"
else
    TIME_DATE="AM"
fi

print_success "Menu Packet"
}

# Restart layanan after install
function enable_services(){
clear
print_install "Enable Service"

# reload systemd
systemctl daemon-reload

# ===== netfilter-persistent (Ubuntu 24 SAFE) =====
if ! dpkg -l | grep -q netfilter-persistent; then
    apt update -y >/dev/null 2>&1
    apt install netfilter-persistent iptables-persistent -y >/dev/null 2>&1
fi

systemctl enable --now netfilter-persistent >/dev/null 2>&1
systemctl restart netfilter-persistent >/dev/null 2>&1

# ===== rc-local (Ubuntu 24) =====
systemctl enable rc-local >/dev/null 2>&1
systemctl start rc-local >/dev/null 2>&1

# ===== cron =====
systemctl enable --now cron >/dev/null 2>&1
systemctl restart cron >/dev/null 2>&1

# ===== service utama =====
systemctl restart nginx >/dev/null 2>&1
systemctl restart xray >/dev/null 2>&1
systemctl restart haproxy >/dev/null 2>&1

print_success "Enable Service"
clear
}

# Fingsi Install Script
function instal(){
    clear

    # ===== BASIC & SYSTEM =====
    first_setup
    base_package
    security_hardening

    # ===== FIREWALL & NETWORK =====
    firewall_setup

    # ===== WEB SERVER =====
    nginx_install

    # ===== XRAY & FOLDER =====
    make_folder_xray
    pasang_domain
    password_default

    # ===== SSL (HARUS SETELAH NGINX) =====
    pasang_ssl

    # ===== CORE SERVICE =====
    install_xray
    ssh
    ins_SSHD
    ins_dropbear

    # ===== TUNNEL & UDP =====
    udp_mini
    ssh_slow

    # ===== MONITORING =====
    ins_vnstat

    # ===== BACKUP & SYSTEM =====
    ins_backup
    ins_swab

    # ===== SECURITY =====
    ins_Fail2ban

    # ===== WEBSOCKET =====
    ins_epro

    # ===== FINAL RESTART SERVICE =====
    ins_restart

    # ===== MENU & PROFILE =====
    menu
    profile

    # ===== ENABLE SERVICE (UBUNTU 24 FIX) =====
    enable_services

    # ===== REBOOT =====
    restart_system
}
# ================== RUN INSTALLER ==================
instal

echo ""

# ================== CLEAN HISTORY ==================
history -c
unset HISTFILE

# ================== CLEAN FILE SISA ==================
rm -rf /root/menu
rm -rf /root/*.zip
rm -rf /root/*.sh
rm -rf /root/LICENSE
rm -rf /root/README.md
rm -rf /root/domain

# ================== SET HOSTNAME ==================
hostnamectl set-hostname "$username"

# ================== SHOW INSTALL TIME ==================
secs_to_human "$(($(date +%s) - ${start}))"

# ================== SUCCESS MESSAGE ==================
echo -e "${green} Script Successfully Installed ${NC}"
echo ""

# ================== REBOOT PROMPT ==================
read -p "$(echo -e "Press ${YELLOW}[ Enter ]${NC} For reboot") "
reboot