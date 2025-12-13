#!/bin/bash

# Warna
Green="\e[92;1m"
RED="\033[31m"
YELLOW="\033[33m"
BLUE="\033[36m"
NC="\033[0m"
GREENBG="\033[42;37m"
REDBG="\033[41;37m"
OK="${Green}  »${NC}"
ERROR="${RED}[ERROR]${NC}"
GRAY="\e[1;30m"
red='\e[1;31m'
green='\e[0;32m'

clear

# Banner
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  » Quick Setup VPN Server (Xray + SSH + Trojan + dll.)"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
sleep 2

# Cek Arsitektur
if [[ $(uname -m) == "x86_64" ]]; then
    echo -e "${OK} Arsitektur Didukung: ${green}$(uname -m)${NC}"
else
    echo -e "${ERROR} Arsitektur Tidak Didukung: ${YELLOW}$(uname -m)${NC}"
    exit 1
fi

# Cek OS
OS_ID=$(grep -w ID /etc/os-release | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g' | xargs)
OS_PRETTY=$(grep -w PRETTY_NAME /etc/os-release | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g' | xargs)
if [[ "$OS_ID" == "ubuntu" || "$OS_ID" == "debian" ]]; then
    echo -e "${OK} OS Didukung: ${green}${OS_PRETTY}${NC}"
else
    echo -e "${ERROR} OS Tidak Didukung: ${YELLOW}${OS_PRETTY}${NC}"
    exit 1
fi

# Cek IP
IP=$(curl -sS https://icanhazip.com)
if [[ "$IP" == "" ]]; then
    echo -e "${ERROR} IP Tidak Terdeteksi"
    exit 1
else
    echo -e "${OK} IP Server: ${green}${IP}${NC}"
fi

echo ""
read -p "Tekan ${green}Enter${NC} untuk melanjutkan instalasi..."
clear

# Cek Root & Virtualisasi
if [[ "${EUID}" -ne 0 ]]; then
    echo "Script harus dijalankan sebagai root"
    exit 1
fi
if [[ "$(systemd-detect-virt)" == "openvz" ]]; then
    echo "OpenVZ tidak didukung"
    exit 1
fi

# Repo
REPO="https://raw.githubusercontent.com/welwel11/project2/main/"

# Fungsi Helper
print_install() {
    echo -e "${green}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW} » $1 ${NC}"
    echo -e "${green}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}
print_success() {
    echo -e "${green}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${Green} » $1 berhasil ${NC}"
    echo -e "${green}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    sleep 1
}

start=$(date +%s)
secs_to_human() {
    echo "Waktu instalasi: $(( ${1} / 3600 )) jam $(( (${1} / 60) % 60 )) menit $(( ${1} % 60 )) detik"
}

# 1. Setup Awal
first_setup() {
    print_install "Setup Dasar"
    timedatectl set-timezone Asia/Jakarta
    apt update -y && apt upgrade -y
    print_success "Timezone & Update"
}

# 2. Install Nginx & HAProxy
nginx_haproxy_install() {
    print_install "Install Nginx & HAProxy"
    apt install nginx -y
    if [[ "$OS_ID" == "debian" ]]; then
        curl https://haproxy.debian.net/bernat.debian.org.gpg | gpg --dearmor > /usr/share/keyrings/haproxy.debian.net.gpg
        echo "deb [signed-by=/usr/share/keyrings/haproxy.debian.net.gpg] http://haproxy.debian.net $(lsb_release -sc)-backports-3.0 main" > /etc/apt/sources.list.d/haproxy.list
        apt update
        apt install haproxy -y
    else
        apt install haproxy -y
    fi
    print_success "Nginx & HAProxy"
}

# 3. Package Dasar
base_package() {
    print_install "Install Package Pendukung"
    apt install -y zip pwgen openssl netcat socat cron bash-completion figlet speedtest-cli vnstat libnss3-dev libsqlite3-dev sed dirmngr build-essential gcc g++ curl wget git screen htop lsof tar ruby unzip p7zip-full python3-pip ca-certificates gnupg jq iptables iptables-persistent netfilter-persistent net-tools dos2unix zlib1g-dev libssl-dev bc rsyslog msmtp-mta bsd-mailx
    print_success "Package Pendukung"
}

# 4. Buat Folder Xray
make_folder_xray() {
    print_install "Buat Folder & File Xray"
    mkdir -p /etc/xray /var/log/xray /var/lib/kyt /etc/vmess /etc/vless /etc/trojan /etc/shadowsocks /etc/ssh /etc/bot /etc/kyt/limit/{vmess,vless,trojan,ssh}/ip /etc/limit/{vmess,vless,trojan,ssh} /usr/bin/xray /var/www/html
    touch /etc/xray/{domain,ipvps,xray.crt,xray.key} /var/log/xray/{access.log,error.log}
    chown -R www-data:www-data /var/log/xray
    print_success "Folder Xray"
}

# 5. Setup Domain
pasang_domain() {
    print_install "Setup Domain"
    echo -e " [1] Domain Pribadi\n [2] Domain Random (Cloudflare)"
    read -p " Pilih (1/2): " opt
    if [[ $opt == "1" ]]; then
        read -p " Masukkan Domain: " domain
        echo "$domain" > /etc/xray/domain
        echo "$domain" > /root/domain
    elif [[ $opt == "2" ]]; then
        wget ${REPO}files/cf.sh && chmod +x cf.sh && ./cf.sh && rm cf.sh
    else
        echo "Pilih salah, menggunakan random."
        wget ${REPO}files/cf.sh && chmod +x cf.sh && ./cf.sh && rm cf.sh
    fi
    print_success "Domain"
}

# 6. Ganti Password Default (fungsi yang hilang)
password_default() {
    print_install "Mengubah Kebijakan Password"
    wget -O /etc/pam.d/common-password "${REPO}files/password"
    chmod +x /etc/pam.d/common-password
    print_success "Password Policy"
}

# 7. Pasang SSL (Acme.sh)
pasang_ssl() {
    print_install "Pasang SSL LetsEncrypt"
    domain=$(cat /etc/xray/domain)
    systemctl stop nginx
    rm -rf /root/.acme.sh
    curl https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
    chmod +x /root/.acme.sh/acme.sh
    /root/.acme.sh/acme.sh --upgrade --auto-upgrade
    /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
    /root/.acme.sh/acme.sh --issue -d $domain --standalone -k ec-256
    /root/.acme.sh/acme.sh --installcert -d $domain --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc
    chmod 644 /etc/xray/xray.*
    print_success "SSL"
}

# 8. Install Xray Core (Latest)
install_xray() {
    print_install "Install Xray Core (Latest)"
    mkdir -p /run/xray && chown www-data:www-data /run/xray
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --beta
    wget -O /etc/xray/config.json "${REPO}config/config.json"
    wget -O /etc/systemd/system/runn.service "${REPO}files/runn.service"
    domain=$(cat /etc/xray/domain)
    wget -O /etc/haproxy/haproxy.cfg "${REPO}config/haproxy.cfg"
    wget -O /etc/nginx/conf.d/xray.conf "${REPO}config/xray.conf"
    wget -O /etc/nginx/nginx.conf "${REPO}config/nginx.conf"
    sed -i "s/xxx/$domain/g" /etc/haproxy/haproxy.cfg /etc/nginx/conf.d/xray.conf
    cat /etc/xray/xray.crt /etc/xray/xray.key > /etc/haproxy/hap.pem
    cat > /etc/systemd/system/xray.service <<EOF
[Unit]
Description=Xray Service
After=network.target

[Service]
User=www-data
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /etc/xray/config.json
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
    print_success "Xray Core"
}

# Fungsi lainnya (ssh, udp, dropbear, vnstat, openvpn, backup, fail2ban, ws, restart, menu, profile, dll.) tetap sama tapi dibersihkan sedikit
# ... (salin fungsi lain dari script asli, kecuali yang sudah diganti di atas)

# Jalankan Urutan Instalasi
first_setup
nginx_haproxy_install
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
ins_openvpn
ins_backup
ins_swab  # Hapus bagian gotop jika mau
ins_Fail2ban
ins_epro
ins_restart
menu
profile
enable_services

# Cleanup & Finish
history -c
rm -rf /root/*.sh /root/*.zip
secs_to_human "$(($(date +%s) - ${start}))"
echo -e "${green}Instalasi Selesai! Server akan reboot.${NC}"
read -p "Tekan Enter untuk reboot..."
reboot