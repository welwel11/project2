#!/bin/bash

# ==========================
# WARNA
# ==========================
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

# ==========================
# EXPORT IP ADDRESS
# ==========================
export IP=$(curl -sS icanhazip.com)

# ==========================
# CLEAR SCREEN
# ==========================
clear

# ==========================
# BANNER
# ==========================
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  » This Will Quick Setup VPN Server On Your Server"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
sleep 2

# ==========================
# CHECK ARCHITECTURE
# ==========================
ARCH=$(uname -m)
if [[ "$ARCH" == "x86_64" ]]; then
    echo -e "${OK} Your Architecture Is Supported ( ${green}${ARCH}${NC} )"
else
    echo -e "${ERROR} Your Architecture Is Not Supported ( ${YELLOW}${ARCH}${NC} )"
    exit 1
fi

# ==========================
# CHECK OS
# ==========================
OS_ID=$(awk -F= '/^ID=/{print $2}' /etc/os-release | tr -d '"')
OS_NAME=$(awk -F= '/^PRETTY_NAME=/{print $2}' /etc/os-release | tr -d '"')

if [[ "$OS_ID" == "ubuntu" || "$OS_ID" == "debian" ]]; then
    echo -e "${OK} Your OS Is Supported ( ${green}${OS_NAME}${NC} )"
else
    echo -e "${ERROR} Your OS Is Not Supported ( ${YELLOW}${OS_NAME}${NC} )"
    exit 1
fi

# ==========================
# IP ADDRESS VALIDATING
# ==========================
if [[ -z "$IP" ]]; then
    echo -e "${ERROR} IP Address ( ${YELLOW}Not Detected${NC} )"
else
    echo -e "${OK} IP Address ( ${green}$IP${NC} )"
fi

# ==========================
# VALIDATE SUCCESSFUL
# ==========================
echo ""
read -p "$(echo -e "Press ${GRAY}[ ${NC}${green}Enter${NC} ${GRAY}]${NC} For Starting Installation") "
echo ""
clear

# ==========================
# ROOT & VIRTUALIZATION CHECK
# ==========================
if [ "${EUID}" -ne 0 ]; then
    echo -e "${ERROR} You need to run this script as root"
    exit 1
fi

if [ "$(systemd-detect-virt)" == "openvz" ]; then
    echo -e "${ERROR} OpenVZ is not supported"
    exit 1
fi

# ==========================
# RE-INSTANTIATING COLORS (SAFE)
# ==========================
red='\e[1;31m'
green='\e[0;32m'
NC='\e[0m'

# ==========================
# SCRIPT PERMISSIONS
# ==========================
MYIP=$(curl -sS ipv4.icanhazip.com)
echo -e "\e[32mloading...\e[0m"
clear

# ==========================
# INSTALL DEPENDENCIES
# ==========================
apt update -y && apt upgrade -y
apt install -y ruby wget curl unzip sudo net-tools iptables iptables-persistent \
chrony ntpdate ruby-full python3 python3-pip vim lsof tar zip p7zip-full \
bash-completion gnupg2 ca-certificates build-essential make cmake git screen socat dnsutils \
vnstat rclone msmtp-mta bsd-mailx netfilter-persistent openvpn easy-rsa wondershaper software-properties-common

gem install lolcat

clear

# ==========================
# REPO
# ==========================
REPO="https://raw.githubusercontent.com/welwel11/project2/main/"

# ==========================
# TIMER FUNCTIONS
# ==========================
start=$(date +%s)
secs_to_human() {
    echo "Installation time : $((${1} / 3600)) hours $(((${1} / 60) % 60)) minute's $((${1} % 60)) seconds"
}

# ==========================
# STATUS FUNCTIONS
# ==========================
print_ok() {
    echo -e "${OK} ${BLUE} $1 ${FONT}"
}

print_install() {
    echo -e "${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}"
    echo -e "${YELLOW} » $1 ${FONT}"
    echo -e "${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}"
    sleep 1
}

print_error() {
    echo -e "${ERROR} ${REDBG} $1 ${FONT}"
}

print_success() {
    if [[ 0 -eq $? ]]; then
        echo -e "${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}"
        echo -e "${Green} » $1 berhasil dipasang${NC}"
        echo -e "${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}"
        sleep 2
    fi
}

### =========================
### CEK ROOT
### =========================
function is_root() {
    if [[ 0 == "$UID" ]]; then
        print_ok "Root user detected. Starting installation process..."
    else
        print_error "The current user is not the root user. Please switch to root and rerun the script."
        exit 1
    fi
}

### =========================
### BUAT DIREKTORI XRAY
### =========================
print_install "Membuat direktori Xray"
mkdir -p /etc/xray
curl -s ifconfig.me > /etc/xray/ipvps
touch /etc/xray/domain
mkdir -p /var/log/xray
chown www-data:www-data /var/log/xray
chmod 755 /var/log/xray
touch /var/log/xray/access.log
touch /var/log/xray/error.log
mkdir -p /var/lib/kyt >/dev/null 2>&1

### =========================
### RAM INFORMATION
### =========================
mem_used=0
mem_total=0
while IFS=":" read -r key value; do
    case $key in
        "MemTotal") mem_total="${value//kB/}" ;;
        "Shmem") ((mem_used+=${value//kB/})) ;;
        "MemFree"|"Buffers"|"Cached"|"SReclaimable") ((mem_used+=${value//kB/})) ;;
    esac
done < /proc/meminfo

Ram_Usage="$((mem_used / 1024))"
Ram_Total="$((mem_total / 1024))"

### =========================
### SYSTEM INFORMATION
### =========================
export tanggal=$(date +"%d-%m-%Y - %X")
export OS_Name=$(awk -F= '/^PRETTY_NAME=/{print $2}' /etc/os-release | tr -d '"')
export Kernel=$(uname -r)
export Arch=$(uname -m)
export IP=$(curl -s https://ipinfo.io/ip/)

### =========================
### FIRST SETUP
### =========================
function first_setup() {
    timedatectl set-timezone Asia/Jakarta
    echo "iptables-persistent iptables-persistent/autosave_v4 boolean true" | debconf-set-selections
    echo "iptables-persistent iptables-persistent/autosave_v6 boolean true" | debconf-set-selections
    print_success "Directory Xray ready"

    OS_ID=$(awk -F= '/^ID=/{print $2}' /etc/os-release | tr -d '"')

    if [[ "$OS_ID" == "ubuntu" ]]; then
        print_install "Setup Dependencies for $OS_Name"
        sudo apt update -y
        apt-get install --no-install-recommends -y software-properties-common haproxy
    elif [[ "$OS_ID" == "debian" ]]; then
        print_install "Setup Dependencies for $OS_Name"
        curl -s https://haproxy.debian.net/bernat.debian.org.gpg | gpg --dearmor >/usr/share/keyrings/haproxy.debian.net.gpg
        echo "deb [signed-by=/usr/share/keyrings/haproxy.debian.net.gpg] http://haproxy.debian.net Bullseye-2.2 main" >/etc/apt/sources.list.d/haproxy.list
        sudo apt-get update
        apt-get -y install haproxy=2.2.*
    else
        print_error "Your OS is not supported ($OS_Name)"
        exit 1
    fi
}

### =========================
### NGINX INSTALL
### =========================
function nginx_install() {
    OS_ID=$(awk -F= '/^ID=/{print $2}' /etc/os-release | tr -d '"')
    if [[ "$OS_ID" == "ubuntu" || "$OS_ID" == "debian" ]]; then
        print_install "Setup nginx for $OS_Name"
        apt-get install -y nginx
        print_success "Nginx installed successfully"
    else
        print_error "Your OS is not supported ($OS_Name)"
    fi
}

### =========================
### BASE PACKAGE
### =========================
function base_package() {
    clear
    print_install "Menginstall Paket Yang Dibutuhkan"

    # Paket dasar
    apt update -y && apt upgrade -y && apt dist-upgrade -y
    apt install -y zip pwgen openssl netcat socat cron bash-completion figlet sudo ntpdate software-properties-common \
    speedtest-cli vnstat libnss3-dev libnspr4-dev pkg-config libpam0g-dev libcap-ng-dev libcap-ng-utils libselinux1-dev \
    libcurl4-nss-dev flex bison make libnss3-tools libevent-dev bc rsyslog dos2unix zlib1g-dev libssl-dev libsqlite3-dev \
    sed dirmngr libxml-parser-perl build-essential gcc g++ python3 python3-pip htop lsof tar wget curl ruby zip unzip p7zip-full \
    msmtp-mta ca-certificates bsd-mailx iptables iptables-persistent netfilter-persistent net-tools openssl gnupg \
    gnupg2 lsb-release shc cmake git screen socat xz-utils apt-transport-https jq openvpn easy-rsa

    # Chrony & time sync
    systemctl enable chronyd
    systemctl restart chronyd
    chronyc sourcestats -v
    chronyc tracking -v
    ntpdate pool.ntp.org

    # Cleanup
    apt-get clean all
    apt-get autoremove -y

    # Remove unwanted services
    apt-get remove --purge -y exim4 ufw firewalld

    # Setup iptables-persistent
    echo "iptables-persistent iptables-persistent/autosave_v4 boolean true" | debconf-set-selections
    echo "iptables-persistent iptables-persistent/autosave_v6 boolean true" | debconf-set-selections

    print_success "Semua Paket Yang Dibutuhkan Telah Terinstall"
}

### =========================
### PASANG DOMAIN
### =========================
function pasang_domain() {
    clear
    echo -e "${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}"
    echo -e "${YELLOW}» SETUP DOMAIN CLOUDFLARE ${FONT}"
    echo -e "${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}"
    echo -e "  [1] Domain Pribadi"
    echo -e "  [2] Domain Bawaan"
    echo -e "${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}"
    
    read -p "  Silahkan Pilih Menu Domain 1 atau 2 (enter) : " host

    if [[ $host == "1" ]]; then
        read -p "   Masukkan Subdomain Anda: " host1
        echo "IP=" >> /var/lib/kyt/ipvps.conf
        echo "$host1" > /etc/xray/domain
        echo "$host1" > /root/domain
        print_success "Domain Pribadi Telah Disimpan"
    elif [[ $host == "2" ]]; then
        wget ${REPO}files/cf.sh -O /root/cf.sh
        chmod +x /root/cf.sh
        /root/cf.sh
        rm -f /root/cf.sh
        print_success "Domain Bawaan Telah Terpasang"
    else
        print_install "Random Subdomain/Domain Digunakan"
    fi
}

### =========================
### RESTART & INFO VPS
### =========================
function restart_system() {
    MYIP=$(curl -sS ipv4.icanhazip.com)
    echo -e "\e[32mloading...\e[0m"
    clear

    # Izin script & user info
    izinsc="https://raw.githubusercontent.com/welwel11/izin/main/"

    username=$(curl -s $izinsc | grep $MYIP | awk '{print $2}')
    echo "$username" > /usr/bin/user

    expx=$(curl -s $izinsc | grep $MYIP | awk '{print $3}')
    echo "$expx" > /usr/bin/e

    # Detail order
    oid=$(cat /usr/bin/ver 2>/dev/null)
    exp=$(cat /usr/bin/e)

    # VPS Info
    DATE=$(date +'%Y-%m-%d')
    TIMEZONE=$(date +'%H:%M:%S')
    ISP=$(curl -s ipinfo.io/org | cut -d " " -f 2-10)

    # Status Expired/Active
    today=$(date +'%Y-%m-%d')
    Exp1=$(curl -s $izinsc | grep $MYIP | awk '{print $4}')
    if [[ "$today" < "$Exp1" ]]; then
        sts="(${green}Active${NC})"
    else
        sts="(${RED}Expired${NC})"
    fi

    # Kirim notif Telegram (opsional)
    CHATID=""
    KEY=""
    URL="https://api.telegram.org/bot$KEY/sendMessage"
    TEXT=# =========================
# Setup Direktori & Info VPS
# =========================
print_install "Membuat direktori Xray"
mkdir -p /etc/xray
curl -s ifconfig.me > /etc/xray/ipvps
touch /etc/xray/domain
mkdir -p /var/log/xray
chown www-data:www-data /var/log/xray
chmod 755 /var/log/xray
touch /var/log/xray/access.log
touch /var/log/xray/error.log
mkdir -p /var/lib/kyt >/dev/null 2>&1

# Ram Information
mem_used=0
mem_total=0
while IFS=":" read -r a b; do
    case $a in
        "MemTotal") ((mem_used+=${b/kB})); mem_total="${b/kB}" ;;
        "Shmem") ((mem_used+=${b/kB})) ;;
        "MemFree" | "Buffers" | "Cached" | "SReclaimable") mem_used="$((mem_used-=${b/kB}))" ;;
    esac
done < /proc/meminfo

Ram_Usage="$((mem_used / 1024))"
Ram_Total="$((mem_total / 1024))"

export tanggal=$(date -d "0 days" +"%d-%m-%Y - %X")
export OS_Name=$(grep -w PRETTY_NAME /etc/os-release | head -n1 | cut -d= -f2 | tr -d '"')
export Kernel=$(uname -r)
export Arch=$(uname -m)
export IP=$(curl -s https://ipinfo.io/ip/)

# =========================
# Setup Environment Sistem
# =========================
function first_setup(){
    timedatectl set-timezone Asia/Jakarta
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
    print_success "Directory Xray Terpasang"

    OS_ID=$(grep -w ID /etc/os-release | head -n1 | cut -d= -f2 | tr -d '"')
    OS_NAME=$(grep -w PRETTY_NAME /etc/os-release | head -n1 | cut -d= -f2 | tr -d '"')

    if [[ "$OS_ID" == "ubuntu" ]]; then
        echo "Setup Dependencies untuk $OS_NAME"
        sudo apt update -y
        apt-get install --no-install-recommends software-properties-common -y
        apt-get update -y
        apt-get install -y haproxy
    elif [[ "$OS_ID" == "debian" ]]; then
        echo "Setup Dependencies untuk $OS_NAME"
        curl -fsSL https://haproxy.debian.net/bernat.debian.org.gpg | gpg --dearmor >/usr/share/keyrings/haproxy.debian.net.gpg
        echo "deb [signed-by=/usr/share/keyrings/haproxy.debian.net.gpg] http://haproxy.debian.net Bullseye-2.2 main" >/etc/apt/sources.list.d/haproxy.list
        sudo apt-get update
        apt-get -y install haproxy=2.2.*
    else
        echo -e "OS tidak didukung: $OS_NAME"
        exit 1
    fi
}

# =========================
# Install Nginx
# =========================
function nginx_install(){
    OS_ID=$(grep -w ID /etc/os-release | head -n1 | cut -d= -f2 | tr -d '"')
    OS_NAME=$(grep -w PRETTY_NAME /etc/os-release | head -n1 | cut -d= -f2 | tr -d '"')

    if [[ "$OS_ID" == "ubuntu" ]]; then
        print_install "Setup Nginx untuk $OS_NAME"
        sudo apt-get install -y nginx
    elif [[ "$OS_ID" == "debian" ]]; then
        print_install "Setup Nginx untuk $OS_NAME"
        apt-get install -y nginx
    else
        echo -e "OS tidak didukung: $OS_NAME"
    fi
}

# =========================
# Paket Dasar & Dependency
# =========================
function base_package(){
    clear
    print_install "Menginstall Paket Dasar"
    apt install -y zip pwgen openssl netcat socat cron bash-completion figlet
    apt update -y
    apt upgrade -y
    apt dist-upgrade -y
    systemctl enable chronyd
    systemctl restart chronyd
    chronyc sourcestats -v
    chronyc tracking -v
    apt install -y ntpdate sudo
    sudo apt-get clean all
    sudo apt-get autoremove -y
    sudo apt-get install -y debconf-utils
    sudo apt-get remove --purge exim4 ufw firewalld -y
    sudo apt-get install -y --no-install-recommends software-properties-common
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
    sudo apt-get install -y speedtest-cli vnstat libnss3-dev libnspr4-dev pkg-config libpam0g-dev \
        libcap-ng-dev libcap-ng-utils libselinux1-dev libcurl4-nss-dev flex bison make libnss3-tools \
        libevent-dev bc rsyslog dos2unix zlib1g-dev libssl-dev libsqlite3-dev sed dirmngr libxml-parser-perl \
        build-essential gcc g++ python htop lsof tar wget curl ruby zip unzip p7zip-full python3-pip \
        libc6 util-linux build-essential msmtp-mta ca-certificates bsd-mailx iptables iptables-persistent \
        netfilter-persistent net-tools openssl ca-certificates gnupg gnupg2 lsb-release gcc shc make cmake \
        git screen socat xz-utils apt-transport-https gnupg1 dnsutils jq openvpn easy-rsa
    print_success "Paket Dasar Terinstall"
}

# =========================
# Setup Domain
# =========================
function pasang_domain(){
    clear
    echo -e "${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}"
    echo -e "${YELLOW}» SETUP DOMAIN CLOUDFLARE ${FONT}"
    echo -e "${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}"
    echo -e "  [1] Domain Pribadi"
    echo -e "  [2] Domain Bawaan"
    echo -e "${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}"
    read -p "  Pilih Menu Domain (1/2): " host
    echo ""
    if [[ $host == "1" ]]; then
        read -p "   Masukkan Subdomain: " host1
        echo "IP=" >> /var/lib/kyt/ipvps.conf
        echo "$host1" > /etc/xray/domain
        echo "$host1" > /root/domain
    elif [[ $host == "2" ]]; then
        wget -q ${REPO}files/cf.sh && chmod +x cf.sh && ./cf.sh
        rm -f /root/cf.sh
    else
        print_install "Random Subdomain/Domain akan digunakan"
        clear
    fi
}

# =========================
# Restart System & Update Info
# =========================
function restart_system(){
    MYIP=$(curl -sS ipv4.icanhazip.com)
    izinsc="https://raw.githubusercontent.com/welwel11/izin/main/izin"

    rm -f /usr/bin/user
    username=$(curl -s $izinsc | grep $MYIP | awk '{print $2}')
    echo "$username" >/usr/bin/user
    expx=$(curl -s $izinsc | grep $MYIP | awk '{print $3}')
    echo "$expx" >/usr/bin/e

    username=$(cat /usr/bin/user)
    exp=$(cat /usr/bin/e)
    DATE=$(date +'%Y-%m-%d')

    ISP=$(curl -s ipinfo.io/org | cut -d " " -f 2-10)
    today=$(date -d "0 days" +"%Y-%m-%d")
    Exp1=$(curl -s $izinsc | grep $MYIP | awk '{print $4}')
    if [[ $today < $Exp1 ]]; then sts="(${green}Active${NC})"; else sts="(${RED}Expired${NC})"; fi

    TIMEZONE=$(printf '%(%H:%M:%S)T')
    TEXT="
<code>━━━━━━━━━━━━━━━━━━━━━━━━━</code>
<b>PREMIUM AUTOSCRIPT</b>
<code>━━━━━━━━━━━━━━━━━━━━━━━━━</code>
<code>User     :</code><code>$username</code>
<code>Domain   :</code><code>$domain</code>
<code>IPVPS    :</code><code>$MYIP</code>
<code>ISP      :</code><code>$ISP</code>
<code>DATE     :</code><code>$DATE</code>
<code>Time     :</code><code>$TIMEZONE</code>
<code>Exp Sc.  :</code><code>$exp</code>
<code>━━━━━━━━━━━━━━━━━━━━━━━━━</code>
<i>Automatic Notifications From Github</i>
"
    curl -s --max-time 10 -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html" "https://api.telegram.org/bot$KEY/sendMessage" >/dev/null
}
clear
### =========================
### PASANG SSL
### =========================
function pasang_ssl() {
    clear
    print_install "Memasang SSL Pada Domain"

    rm -f /etc/xray/xray.key /etc/xray/xray.crt
    domain=$(cat /root/domain)

    # Stop webserver sementara
    STOPWEBSERVER=$(lsof -i:80 | awk 'NR==2 {print $1}')
    systemctl stop $STOPWEBSERVER 2>/dev/null
    systemctl stop nginx 2>/dev/null

    rm -rf /root/.acme.sh
    mkdir -p /root/.acme.sh

    curl -s https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
    chmod +x /root/.acme.sh/acme.sh

    /root/.acme.sh/acme.sh --upgrade --auto-upgrade
    /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
    /root/.acme.sh/acme.sh --issue -d $domain --standalone -k ec-256
    ~/.acme.sh/acme.sh --installcert -d $domain \
        --fullchainpath /etc/xray/xray.crt \
        --keypath /etc/xray/xray.key --ecc

    chmod 644 /etc/xray/xray.key
    print_success "SSL Certificate Terpasang"
}

### =========================
### MAKE FOLDER XRAY
### =========================
function make_folder_xray() {
    # Hapus database lama
    rm -f /etc/vmess/.vmess.db /etc/vless/.vless.db /etc/trojan/.trojan.db \
          /etc/shadowsocks/.shadowsocks.db /etc/ssh/.ssh.db /etc/bot/.bot.db \
          /etc/user-create/user.log

    # Buat folder
    mkdir -p /etc/{bot,xray,vmess,vless,trojan,shadowsocks,ssh,user-create} \
             /usr/bin/xray /var/log/xray /var/www/html \
             /etc/kyt/limit/{vmess,vless,trojan,ssh}/ip \
             /etc/limit/{vmess,vless,trojan,ssh}

    chmod +x /var/log/xray

    # Buat file kosong
    touch /etc/xray/domain /var/log/xray/{access.log,error.log} \
          /etc/vmess/.vmess.db /etc/vless/.vless.db /etc/trojan/.trojan.db \
          /etc/shadowsocks/.shadowsocks.db /etc/ssh/.ssh.db /etc/bot/.bot.db \
          /etc/user-create/user.log

    # Isi database awal
    for file in /etc/vmess/.vmess.db /etc/vless/.vless.db /etc/trojan/.trojan.db \
                /etc/shadowsocks/.shadowsocks.db /etc/ssh/.ssh.db; do
        echo "& plughin Account" >> "$file"
    done

    echo "echo -e 'Vps Config User Account'" >> /etc/user-create/user.log
}

### =========================
### INSTALL XRAY
### =========================
function install_xray() {
    clear
    print_install "Core Xray Latest Version"

    domainSock_dir="/run/xray"
    mkdir -p $domainSock_dir
    chown www-data:www-data $domainSock_dir

    # Ambil versi Xray terbaru
    latest_version=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases | \
                     grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)
    
    bash -c "$(curl -sL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data --version $latest_version

    # Ambil config server
    wget -q -O /etc/xray/config.json "${REPO}config/config.json"
    wget -q -O /etc/systemd/system/runn.service "${REPO}files/runn.service"

    domain=$(cat /etc/xray/domain)
    IPVS=$(cat /etc/xray/ipvps)
    print_success "Core Xray Terinstall"

    # Setup Nginx & Haproxy
    clear
    curl -s ipinfo.io/city >> /etc/xray/city
    curl -s ipinfo.io/org | cut -d " " -f 2-10 >> /etc/xray/isp

    print_install "Memasang Konfigurasi Packet"
    wget -q -O /etc/haproxy/haproxy.cfg "${REPO}config/haproxy.cfg"
    wget -q -O /etc/nginx/conf.d/xray.conf "${REPO}config/xray.conf"
    
    sed -i "s/xxx/${domain}/g" /etc/haproxy/haproxy.cfg
    sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/xray.conf
    curl -s ${REPO}config/nginx.conf > /etc/nginx/nginx.conf

    cat /etc/xray/xray.crt /etc/xray/xray.key | tee /etc/haproxy/hap.pem

    chmod +x /etc/systemd/system/runn.service

    # Create systemd service untuk Xray
    rm -rf /etc/systemd/system/xray.service.d
    cat >/etc/systemd/system/xray.service <<EOF
[Unit]
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

    print_success "Konfigurasi Packet Selesai"
}

### =========================
### SSH CONFIGURATION
### =========================
function ssh() {
    clear
    print_install "Memasang Password SSH"

    # Download konfigurasi PAM untuk password
    wget -q -O /etc/pam.d/common-password "${REPO}files/password"
    chmod 644 /etc/pam.d/common-password

    # Reconfigure keyboard non-interaktif
    DEBIAN_FRONTEND=noninteractive dpkg-reconfigure keyboard-configuration
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/altgr select The default for the keyboard layout"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/compose select No compose key"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/ctrl_alt_bksp boolean false"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/layoutcode string de"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/layout select English"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/modelcode string pc105"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/model select Generic 105-key (Intl) PC"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/optionscode string "
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/store_defaults_in_debconf_db boolean true"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/switch select No temporary switch"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/toggle select No toggling"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_config_layout boolean true"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_config_options boolean true"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_layout boolean true"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_options boolean true"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/variantcode string "
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/variant select English"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/xkb-keymap select "

    cd ~

    # Buat file systemd rc-local.service
    cat >/etc/systemd/system/rc-local.service <<-EOF
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
EOF

    # Buat rc.local default
    cat >/etc/rc.local <<-EOF
#!/bin/sh -e
# rc.local
# By default this script does nothing.
exit 0
EOF

    chmod +x /etc/rc.local

    # Enable rc-local service
    systemctl enable rc-local
    systemctl start rc-local.service

    # Disable IPv6
    echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
    grep -qxF 'echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local || \
        sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local

    print_success "Password SSH dan Pengaturan System selesai"
}
### =========================
### UPDATE TIME & LOCALE
### =========================
function update_system(){
    clear
    print_install "Mengatur Timezone & Locale"

    # Set timezone GMT+7
    ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime

    # Disable AcceptEnv pada ssh
    sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config

    print_success "Password SSH & System Locale"
}

### =========================
### UDP MINI & LIMIT IP SERVICE
### =========================
function udp_mini(){
    clear
    print_install "Memasang Service Limit IP & Quota"

    # Pasang FV-Tunnel
    wget -q https://raw.githubusercontent.com/welwel11/project2/main/config/fv-tunnel -O /tmp/fv-tunnel
    chmod +x /tmp/fv-tunnel
    /tmp/fv-tunnel

    # Installing UDP Mini
    mkdir -p /usr/local/kyt/
    wget -q -O /usr/local/kyt/udp-mini "${REPO}files/udp-mini"
    chmod +x /usr/local/kyt/udp-mini

    for i in 1 2 3; do
        wget -q -O /etc/systemd/system/udp-mini-${i}.service "${REPO}files/udp-mini-${i}.service"
        systemctl disable udp-mini-${i}
        systemctl stop udp-mini-${i} 2>/dev/null
        systemctl enable udp-mini-${i}
        systemctl start udp-mini-${i}
    done

    print_success "Limit IP Service Terpasang"
}

### =========================
### SLOWDNS SERVER
### =========================
function ssh_slow(){
    clear
    print_install "Memasang Modul SlowDNS Server"

    wget -q -O /tmp/nameserver "${REPO}files/nameserver"
    chmod +x /tmp/nameserver
    bash /tmp/nameserver | tee /root/install.log

    print_success "SlowDNS Terpasang"
}

### =========================
### INSTALL SSHD
### =========================
function ins_SSHD(){
    clear
    print_install "Memasang SSHD"

    wget -q -O /etc/ssh/sshd_config "${REPO}files/sshd"
    chmod 600 /etc/ssh/sshd_config

    systemctl restart ssh
    systemctl status ssh --no-pager
    print_success "SSHD Terpasang"
}

### =========================
### INSTALL DROPBEAR
### =========================
function ins_dropbear(){
    clear
    print_install "Menginstall Dropbear"

    apt-get install -y dropbear >/dev/null 2>&1
    wget -q -O /etc/default/dropbear "${REPO}config/dropbear.conf"
    chmod 644 /etc/default/dropbear

    systemctl restart dropbear
    systemctl status dropbear --no-pager

    print_success "Dropbear Terpasang"
}

### =========================
### INSTALL VNSTAT
### =========================
function ins_vnstat(){
    clear
    print_install "Menginstall Vnstat"

    # Install dependencies
    apt -y install vnstat libsqlite3-dev > /dev/null 2>&1
    systemctl restart vnstat

    # Compile Vnstat terbaru
    wget -q https://humdi.net/vnstat/vnstat-2.6.tar.gz -O /tmp/vnstat-2.6.tar.gz
    tar zxvf /tmp/vnstat-2.6.tar.gz -C /tmp
    cd /tmp/vnstat-2.6
    ./configure --prefix=/usr --sysconfdir=/etc && make && make install
    cd
    vnstat -u -i $NET
    sed -i "s/Interface \"eth0\"/Interface \"$NET\"/g" /etc/vnstat.conf
    chown vnstat:vnstat /var/lib/vnstat -R
    systemctl enable vnstat
    systemctl restart vnstat
    systemctl status vnstat --no-pager
    rm -rf /tmp/vnstat-2.6 /tmp/vnstat-2.6.tar.gz

    print_success "Vnstat Terpasang"
}

### =========================
### INSTALL OPENVPN
### =========================
function ins_openvpn(){
    clear
    print_install "Menginstall OpenVPN"

    wget -q -O /tmp/openvpn "${REPO}files/openvpn"
    chmod +x /tmp/openvpn
    bash /tmp/openvpn
    systemctl restart openvpn

    print_success "OpenVPN Terpasang"
}

### =========================
### INSTALL BACKUP SERVER
### =========================
function ins_backup(){
    clear
    print_install "Memasang Backup Server"

    # Rclone
    apt install -y rclone
    printf "q\n" | rclone config
    mkdir -p /root/.config/rclone
    wget -q -O /root/.config/rclone/rclone.conf "${REPO}config/rclone.conf"

    # Wondershaper
    git clone https://github.com/magnific0/wondershaper.git /tmp/wondershaper
    cd /tmp/wondershaper
    sudo make install
    cd && rm -rf /tmp/wondershaper
    echo > /home/limit

    # Mail
    apt install -y msmtp-mta ca-certificates bsd-mailx
    cat <<EOF >/etc/msmtprc
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
logfile ~/.msmtp.log
EOF
    chown -R www-data:www-data /etc/msmtprc

    wget -q -O /etc/ipserver "${REPO}files/ipserver"
    bash /etc/ipserver

    print_success "Backup Server Terpasang"
}

function ins_swab(){
    clear
    print_install "Memasang Swap 1G & Gotop"

    # Pasang Gotop terbaru
    gotop_latest=$(curl -s https://api.github.com/repos/xxxserxxx/gotop/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n1)
    gotop_link="https://github.com/xxxserxxx/gotop/releases/download/v$gotop_latest/gotop_v${gotop_latest}_linux_amd64.deb"
    wget -q -O /tmp/gotop.deb "$gotop_link"
    dpkg -i /tmp/gotop.deb >/dev/null 2>&1
    rm -f /tmp/gotop.deb

    # Buat swap sebesar 1G
    dd if=/dev/zero of=/swapfile bs=1024 count=1048576 status=progress
    mkswap /swapfile
    chown root:root /swapfile
    chmod 600 /swapfile
    swapon /swapfile

    # Tambahkan ke fstab jika belum ada
    grep -qxF '/swapfile swap swap defaults 0 0' /etc/fstab || \
        echo '/swapfile swap swap defaults 0 0' >> /etc/fstab

    # Sinkronisasi jam
    chronyd -q 'server 0.id.pool.ntp.org iburst'
    chronyc sourcestats -v
    chronyc tracking -v

    # Pasang BBR
    wget -q -O /tmp/bbr.sh "${REPO}files/bbr.sh"
    chmod +x /tmp/bbr.sh
    bash /tmp/bbr.sh
    rm -f /tmp/bbr.sh

    print_success "Swap 1G Terpasang & BBR Aktif"
}

function ins_Fail2ban(){
    clear
    print_install "Menginstall Fail2ban"
    apt -y install fail2ban >/dev/null 2>&1
    systemctl enable --now fail2ban
    systemctl restart fail2ban
    systemctl status fail2ban --no-pager

    clear
    # Setup Banner
    BANNER_FILE="/etc/kyt.txt"
    wget -q -O "$BANNER_FILE" "${REPO}files/issue.net"
    echo "Banner $BANNER_FILE" >>/etc/ssh/sshd_config
    sed -i "s@DROPBEAR_BANNER=\"\"@DROPBEAR_BANNER=\"$BANNER_FILE\"@g" /etc/default/dropbear
    print_success "Fail2ban & Banner SSH/Dropbear Terpasang"

    # Anti DDoS & Bruteforce Protection (Basic)
    print_install "Menambahkan proteksi DDoS dasar"
    # Limit new SSH connections: max 3 koneksi per 60 detik per IP
    iptables -I INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --set
    iptables -I INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 4 -j DROP

    # Limit RDP / WS ports
    WS_PORTS=(80 443 4433 8443 2082 2087 2096)
    for port in "${WS_PORTS[@]}"; do
        iptables -I INPUT -p tcp --dport $port -m conntrack --ctstate NEW -m limit --limit 25/minute --limit-burst 50 -j ACCEPT
    done

    # Block invalid packets
    iptables -A INPUT -m state --state INVALID -j DROP
    iptables -A FORWARD -m state --state INVALID -j DROP

    iptables-save > /etc/iptables.up.rules
    netfilter-persistent save
    netfilter-persistent reload
    print_success "Anti-DDoS dasar diaktifkan"
}

function ins_epro(){
    clear
    print_install "Menginstall ePro WebSocket Proxy"

    # Download binary dan konfigurasi
    wget -q -O /usr/bin/ws "${REPO}files/ws"
    wget -q -O /usr/bin/tun.conf "${REPO}config/tun.conf"
    wget -q -O /etc/systemd/system/ws.service "${REPO}files/ws.service"

    chmod +x /usr/bin/ws /etc/systemd/system/ws.service
    chmod 644 /usr/bin/tun.conf

    systemctl disable ws
    systemctl stop ws
    systemctl enable ws
    systemctl start ws
    systemctl restart ws

    # Download rules geodata Xray
    wget -q -O /usr/local/share/xray/geosite.dat \
        "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"
    wget -q -O /usr/local/share/xray/geoip.dat \
        "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"

    # Pasang ftvpn
    wget -q -O /usr/sbin/ftvpn "${REPO}files/ftvpn"
    chmod +x /usr/sbin/ftvpn

    # Firewall Anti-Torrent
    TORRENT_RULES=(
        "get_peers" "announce_peer" "find_node"
        "BitTorrent" "BitTorrent protocol" "peer_id="
        ".torrent" "announce.php?passkey=" "torrent"
        "announce" "info_hash"
    )
    for rule in "${TORRENT_RULES[@]}"; do
        iptables -A FORWARD -m string --algo bm --string "$rule" -j DROP
    done

    # Anti DDoS ringan: limit koneksi WS ports
    WS_PORTS=(80 443 4433 8443 2082 2087 2096)
    for port in "${WS_PORTS[@]}"; do
        iptables -I INPUT -p tcp --dport $port -m conntrack --ctstate NEW -m limit --limit 25/minute --limit-burst 50 -j ACCEPT
    done

    # Block invalid packets
    iptables -A INPUT -m state --state INVALID -j DROP
    iptables -A FORWARD -m state --state INVALID -j DROP

    iptables-save > /etc/iptables.up.rules
    netfilter-persistent save
    netfilter-persistent reload

    # Bersihkan sistem
    apt autoclean -y >/dev/null 2>&1
    apt autoremove -y >/dev/null 2>&1

    print_success "ePro WebSocket Proxy Terpasang & Anti-DDoS Aktif"
}

function ins_restart(){
    clear
    print_install "Restarting All Services"

    # Restart Services
    for svc in nginx ssh dropbear fail2ban vnstat haproxy cron xray ws netfilter-persistent; do
        if systemctl list-unit-files | grep -q "$svc"; then
            systemctl restart $svc
        else
            /etc/init.d/$svc restart >/dev/null 2>&1
        fi
    done

    # Enable Services to auto-start
    for svc in nginx xray rc-local dropbear cron haproxy netfilter-persistent ws fail2ban; do
        systemctl enable --now $svc >/dev/null 2>&1
    done

    # Clear bash history for security
    history -c
    echo "unset HISTFILE" >> /etc/profile

    # Remove temporary cert files
    rm -f /root/key.pem /root/cert.pem

    print_success "All Services Restarted & Secured"
}

# Install Menu Utilities
function menu(){
    clear
    print_install "Memasang Menu Packet"
    
    # Download & unzip menu
    wget -q ${REPO}menu/menu.zip
    unzip -qq menu.zip
    chmod +x menu/*
    mv menu/* /usr/local/sbin/
    
    # Cleanup
    rm -rf menu menu.zip

    print_success "Menu Packet Terpasang"
}

# Setup Default Profile & Cron Jobs
function profile(){
    clear
    # Default login profile
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

    # Cron Jobs
    cat >/etc/cron.d/xp_all <<'END'
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
2 0 * * * root /usr/local/sbin/xp
END

    cat >/etc/cron.d/logclean <<'END'
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/20 * * * * root /usr/local/sbin/clearlog
END

    cat >/etc/cron.d/daily_reboot <<'END'
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 3 * * * root /sbin/reboot
END

    cat >/etc/cron.d/limit_ip <<'END'
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/2 * * * * root /usr/local/sbin/limit-ip
END

    cat >/etc/cron.d/limit_ip2 <<'END'
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/2 * * * * root /usr/bin/limit-ip
END

    # Clear logs frequently for security
    echo "*/1 * * * * root echo -n > /var/log/nginx/access.log" >/etc/cron.d/log.nginx
    echo "*/1 * * * * root echo -n > /var/log/xray/access.log" >/etc/cron.d/log.xray

    # Restart cron to apply jobs
    service cron restart

    # Daily reboot marker
    echo "5" >/home/daily_reboot

    # Setup rc-local service
    cat >/etc/systemd/system/rc-local.service <<'EOF'
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
EOF

    # Secure shells
    grep -qxF "/bin/false" /etc/shells || echo "/bin/false" >>/etc/shells
    grep -qxF "/usr/sbin/nologin" /etc/shells || echo "/usr/sbin/nologin" >>/etc/shells

    # rc.local setup: anti-DDOS ringan untuk DNS/UDP
    cat >/etc/rc.local <<'EOF'
#!/bin/sh -e
# rc.local
# By default this script does nothing.

# Allow internal DNS & redirect UDP 53 to 5300
iptables -I INPUT -p udp --dport 5300 -j ACCEPT
iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300

# Reload firewall
systemctl restart netfilter-persistent

exit 0
EOF

    chmod +x /etc/rc.local

    # Determine AM/PM for potential logging or messages
    AUTOREB=$(cat /home/daily_reboot)
    if [ "$AUTOREB" -gt 11 ]; then
        TIME_DATE="PM"
    else
        TIME_DATE="AM"
    fi

    print_success "Menu Packet & Default Profile Terpasang"
}

# Restart & Enable Semua Layanan Setelah Install
function enable_services(){
    clear
    print_install "Mengaktifkan Semua Layanan"
    
    systemctl daemon-reload
    
    # Enable service penting
    systemctl enable --now rc-local
    systemctl enable --now cron
    systemctl enable --now netfilter-persistent
    systemctl enable --now nginx
    systemctl enable --now xray
    systemctl enable --now haproxy
    systemctl enable --now ws
    systemctl enable --now dropbear
    systemctl enable --now fail2ban

    # Restart service untuk memastikan aktif
    systemctl restart nginx
    systemctl restart xray
    systemctl restart cron
    systemctl restart haproxy
    systemctl restart netfilter-persistent
    systemctl restart ws
    systemctl restart dropbear
    systemctl restart fail2ban

    print_success "Semua Layanan Telah Diaktifkan"
    clear
}

# Fungsi utama untuk instalasi seluruh paket VPS
function instal(){
    clear
    print_install "Memulai Instalasi VPS"

    # Setup dasar
    first_setup
    nginx_install
    base_package
    make_folder_xray
    pasang_domain
    password_default
    pasang_ssl
    install_xray

    # Layanan SSH & Dropbear
    ssh
    udp_mini
    ssh_slow
    ins_SSHD
    ins_dropbear

    # Monitoring & Backup
    ins_vnstat
    ins_backup
    ins_swab

    # Keamanan & WebSocket
    ins_Fail2ban
    ins_epro

    # Restart & optimasi layanan
    ins_restart
    menu
    profile
    enable_services
    restart_system

    # Pembersihan file sementara & history
    history -c
    rm -rf /root/menu /root/*.zip /root/*.sh /root/LICENSE /root/README.md /root/domain
    unset HISTFILE

    # Set hostname VPS sesuai username
    sudo hostnamectl set-hostname "$username"

    # Tampilkan durasi instalasi
    secs_to_human "$(($(date +%s) - ${start}))"

    echo -e "${green} Script Berhasil Terinstall ${FONT}"
    echo ""
    read -p "$(echo -e "Tekan ${YELLOW}[Enter]${NC} Untuk Reboot VPS") "
    reboot
