#!/bin/bash
# ===================================================
# Definisi Warna
# ===================================================
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

# ===================================================
# Hapus Layar
# ===================================================
clear
clear && clear && clear
clear; clear; clear

# ===================================================
# Ekspor Alamat IP
# ===================================================
export IP=$(curl -sS icanhazip.com)

# ===================================================
# Banner
# ===================================================
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  » This Will Quick Setup VPN Server On Your Server"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
sleep 2

# ===================================================
# Pemeriksaan Arsitektur OS
# ===================================================
if [[ $(uname -m) == "x86_64" ]]; then
    echo -e "${OK} Your Architecture Is Supported ( ${green}$(uname -m)${NC} )"
else
    echo -e "${ERROR} Your Architecture Is Not Supported ( ${YELLOW}$(uname -m)${NC} )"
    exit 1
fi

# ===================================================
# Pemeriksaan OS
# ===================================================
OS_ID=$(awk -F= '/^ID=/{print $2}' /etc/os-release | tr -d '"')
OS_NAME=$(awk -F= '/^PRETTY_NAME=/{print $2}' /etc/os-release | tr -d '"')

if [[ "$OS_ID" == "ubuntu" || "$OS_ID" == "debian" ]]; then
    echo -e "${OK} Your OS Is Supported ( ${green}$OS_NAME${NC} )"
else
    echo -e "${ERROR} Your OS Is Not Supported ( ${YELLOW}$OS_NAME${NC} )"
    exit 1
fi

# ===================================================
# Validasi Alamat IP
# ===================================================
if [[ -z "$IP" ]]; then
    echo -e "${ERROR} IP Address ( ${YELLOW}Not Detected${NC} )"
else
    echo -e "${OK} IP Address ( ${green}$IP${NC} )"
fi

# ===================================================
# Validasi Berhasil & Pemeriksaan Root
# ===================================================
echo ""
read -p "$(echo -e "Press ${GRAY}[ ${NC}${green}Enter${NC} ${GRAY}]${NC} For Starting Installation") "
echo ""
clear

if [ "${EUID}" -ne 0 ]; then
    echo "You need to run this script as root"
    exit 1
fi

if [ "$(systemd-detect-virt)" == "openvz" ]; then
    echo "OpenVZ is not supported"
    exit 1
fi

# ===================================================
# Muat IP & Mulai Instalasi
# ===================================================
MYIP=$(curl -sS ipv4.icanhazip.com)
echo -e "\e[32mloading...\e[0m"
clear

# ===================================================
# Perbarui Sistem
# ===================================================
apt update -y && apt upgrade -y

apt install -y software-properties-common curl wget unzip sudo net-tools \
iptables iptables-persistent netfilter-persistent chrony ntpdate \
ruby-full python3 python3-pip vim lsof tar zip p7zip-full \
bash-completion gnupg2 ca-certificates build-essential make cmake git screen socat dnsutils \
vnstat rclone msmtp-mta bsd-mailx openvpn easy-rsa

clear

# ===================================================
# URL repositori
# ===================================================
REPO="https://raw.githubusercontent.com/welwel11/project2/main/"

# ===================================================
# Pengaturan Waktu
# ===================================================
start=$(date +%s)
secs_to_human() {
    echo "Installation time : $((${1} / 3600)) hours $(((${1} / 60) % 60)) minute's $((${1} % 60)) seconds"
}

# ===================================================
# Fungsi Status
# ===================================================
function print_ok() {
    echo -e "${OK} ${BLUE} $1 ${FONT}"
}

function print_install() {
    echo -e "${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}"
    echo -e "${YELLOW} » $1 ${FONT}"
    echo -e "${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}"
    sleep 1
}

function print_error() {
    echo -e "${ERROR} ${REDBG} $1 ${FONT}"
}

function print_success() {
    if [[ 0 -eq $? ]]; then
        echo -e "${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}"
        echo -e "${Green} » $1 berhasil dipasang"
        echo -e "${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}"
        sleep 2
    fi
}

# ===================================================
# Pemeriksaan Root
# ===================================================
function is_root() {
    if [[ 0 == "$UID" ]]; then
        print_ok "Root user Start installation process"
    else
        print_error "The current user is not the root user, please switch to the root user and run the script again"
        exit 1
    fi
}

# ===================================================
# Menyiapkan Direktori & File
# ===================================================
print_install "Membuat direktori xray"

mkdir -p /etc/xray
curl -s ifconfig.me > /etc/xray/ipvps
touch /etc/xray/domain

mkdir -p /var/log/xray
chown www-data.www-data /var/log/xray
chmod +x /var/log/xray
touch /var/log/xray/access.log
touch /var/log/xray/error.log

mkdir -p /var/lib/kyt >/dev/null 2>&1

# ===================================================
# Informasi RAM
# ===================================================
mem_used=0
mem_total=0
while IFS=":" read -r a b; do
    case $a in
        "MemTotal") ((mem_used+=${b/kB})); mem_total="${b/kB}" ;;
        "Shmem") ((mem_used+=${b/kB})) ;;
        "MemFree"|"Buffers"|"Cached"|"SReclaimable")
            mem_used="$((mem_used-=${b/kB}))"
        ;;
    esac
done < /proc/meminfo
Ram_Usage="$((mem_used / 1024))"
Ram_Total="$((mem_total / 1024))"

export tanggal=$(date -d "0 days" +"%d-%m-%Y - %X")
export OS_Name=$(awk -F= '/^PRETTY_NAME/{print $2}' /etc/os-release | tr -d '"')
export Kernel=$(uname -r)
export Arch=$(uname -m)
export IP=$(curl -s https://ipinfo.io/ip/)

# ===================================================
# Pengaturan Awal
# ===================================================
function first_setup() {
    timedatectl set-timezone Asia/Jakarta
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
    print_success "Directory Xray"

    OS_ID=$(awk -F= '/^ID/{print $2}' /etc/os-release | tr -d '"')
    PRETTY_NAME=$(awk -F= '/^PRETTY_NAME/{print $2}' /etc/os-release | tr -d '"')

    if [[ "$OS_ID" == "ubuntu" ]]; then
        echo "Setup Dependencies $PRETTY_NAME"
        sudo apt update -y
        apt-get install --no-install-recommends software-properties-common -y
        add-apt-repository ppa:vbernat/haproxy-3.0 -y
        apt-get install -y haproxy=3.0.*
    elif [[ "$OS_ID" == "debian" ]]; then
        echo "Setup Dependencies For OS $PRETTY_NAME"
        curl https://haproxy.debian.net/bernat.debian.org.gpg | gpg --dearmor >/usr/share/keyrings/haproxy.debian.net.gpg
        echo deb "[signed-by=/usr/share/keyrings/haproxy.debian.net.gpg]" http://haproxy.debian.net Bullseye-2.6 main >/etc/apt/sources.list.d/haproxy.list
        sudo apt-get update -y
        apt-get install -y haproxy=2.6.*
    else
        echo -e " Your OS Is Not Supported ($PRETTY_NAME)"
        exit 1
    fi
}

# ===================================================
# Instalasi Nginx
# ===================================================
function nginx_install() {
    OS_ID=$(awk -F= '/^ID/{print $2}' /etc/os-release | tr -d '"')
    PRETTY_NAME=$(awk -F= '/^PRETTY_NAME/{print $2}' /etc/os-release | tr -d '"')

    if [[ "$OS_ID" == "ubuntu" ]]; then
        print_install "Setup nginx For OS $PRETTY_NAME"
        sudo apt-get install -y nginx
    elif [[ "$OS_ID" == "debian" ]]; then
        print_success "Setup nginx For OS $PRETTY_NAME"
        apt-get install -y nginx
    else
        echo -e " Your OS Is Not Supported ($PRETTY_NAME)"
    fi
}

# ===================================================
# Instalasi Paket Dasar
# ===================================================
function base_package() {
    clear
    print_install "Menginstall Packet Yang Dibutuhkan"

    apt install -y zip pwgen openssl netcat socat cron bash-completion figlet sudo ntpdate speedtest-cli vnstat \
        libnss3-dev libnspr4-dev pkg-config libpam0g-dev libcap-ng-dev libcap-ng-utils libselinux1-dev \
        libcurl4-nss-dev flex bison make libnss3-tools libevent-dev bc rsyslog dos2unix zlib1g-dev libssl-dev \
        libsqlite3-dev sed dirmngr libxml-parser-perl build-essential gcc g++ python htop lsof tar wget curl ruby \
        zip unzip p7zip-full python3-pip libc6 util-linux msmtp-mta ca-certificates bsd-mailx iptables \
        iptables-persistent netfilter-persistent net-tools openssl gnupg gnupg2 lsb-release shc cmake git screen \
        socat xz-utils apt-transport-https gnupg1 dnsutils cron bash-completion chrony jq openvpn easy-rsa

    apt update -y && apt upgrade -y && apt dist-upgrade -y
    systemctl enable chronyd && systemctl restart chronyd
    chronyc sourcestats -v && chronyc tracking -v
    ntpdate pool.ntp.org
    sudo apt-get clean all
    sudo apt-get autoremove -y
    sudo apt-get remove --purge exim4 ufw firewalld -y
    print_success "Packet Yang Dibutuhkan"
}

# ===================================================
# Pengaturan Domain
# ===================================================
function pasang_domain() {
    clear
    echo -e "${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}"
    echo -e "${YELLOW}» SETUP DOMAIN CLOUDFLARE ${FONT}"
    echo -e "${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}"
    echo -e "  [1] Domain Pribadi"
    echo -e "  [2] Domain Bawaan"
    echo -e "${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}"
    read -p "  Silahkan Pilih Menu Domain 1 or 2 (enter) : " host
    echo ""

    if [[ $host == "1" ]]; then
        read -p "   Masukan Subdomain: " host1
        echo "IP=" >> /var/lib/kyt/ipvps.conf
        echo $host1 > /etc/xray/domain
        echo $host1 > /root/domain
    elif [[ $host == "2" ]]; then
        wget ${REPO}files/cf.sh && chmod +x cf.sh && ./cf.sh
        rm -f /root/cf.sh
        clear
    else
        print_install "Random Subdomain/Domain is Used"
clear
fi
}

# ===================================================
# GANTI PASSWORD DEFAULT & Informasi VPS
# ===================================================
clear
function restart_system() {
    # IZIN SCRIPT
    MYIP=$(curl -sS ipv4.icanhazip.com)
    echo -e "\e[32mloading...\e[0m" 
    clear

    izinsc="https://raw.githubusercontent.com/welwel11/izin/main/izin"

    # USERNAME
    rm -f /usr/bin/user
    username=$(curl $izinsc | grep $MYIP | awk '{print $2}')
    echo "$username" >/usr/bin/user

    expx=$(curl $izinsc | grep $MYIP | awk '{print $3}')
    echo "$expx" >/usr/bin/e

    # DETAIL ORDER
    username=$(cat /usr/bin/user)
    oid=$(cat /usr/bin/ver)
    exp=$(cat /usr/bin/e)

    clear

    # CERTIFICATE STATUS
    d1=$(date -d "$valid" +%s)
    d2=$(date -d "$today" +%s)
    certificate=$(((d1 - d2) / 86400))

    # VPS Information
    DATE=$(date +'%Y-%m-%d')
    datediff() {
        d1=$(date -d "$1" +%s)
        d2=$(date -d "$2" +%s)
        echo -e "$COLOR1 $NC Expiry In   : $(( (d1 - d2) / 86400 )) Days"
    }
    mai="datediff $Exp $DATE"

    ISP=$(curl -s ipinfo.io/org | cut -d " " -f 2-10 )

    # Status Expired / Active
    Info="(${green}Active${NC})"
    Error="(${RED}ExpiRED${NC})"
    today=$(date -d "0 days" +"%Y-%m-%d")
    Exp1=$(curl $izinsc | grep $MYIP | awk '{print $4}')

    if [[ $today < $Exp1 ]]; then
        sts="${Info}"
    else
        sts="${Error}"
    fi

    # Telegram Notification
    TIMES="10"
    CHATID=""
    KEY=""
    URL="https://api.telegram.org/bot$KEY/sendMessage"
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
"'&reply_markup={"inline_keyboard":[[{"text":"ᴏʀᴅᴇʀ","url":"t.me"}]]}' 

    curl -s --max-time $TIMES -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html" $URL >/dev/null
}

# ===================================================
# Pasang SSL Certificate
# ===================================================
function pasang_ssl() {
    clear
    print_install "Memasang SSL Pada Domain"

    rm -rf /etc/xray/xray.key
    rm -rf /etc/xray/xray.crt
    domain=$(cat /root/domain)

    STOPWEBSERVER=$(lsof -i:80 | awk 'NR==2 {print $1}')
    rm -rf /root/.acme.sh
    mkdir -p /root/.acme.sh

    systemctl stop $STOPWEBSERVER
    systemctl stop nginx

    curl https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
    chmod +x /root/.acme.sh/acme.sh
    /root/.acme.sh/acme.sh --upgrade --auto-upgrade
    /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
    /root/.acme.sh/acme.sh --issue -d $domain --standalone -k ec-256
    ~/.acme.sh/acme.sh --installcert -d $domain --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc
    chmod 777 /etc/xray/xray.key

    print_success "SSL Certificate"
}

# ===================================================
# Membuat folder dan database untuk Xray dan plugin
# ===================================================
function make_folder_xray() {
    # Hapus database lama
    rm -rf /etc/vmess/.vmess.db
    rm -rf /etc/vless/.vless.db
    rm -rf /etc/trojan/.trojan.db
    rm -rf /etc/shadowsocks/.shadowsocks.db
    rm -rf /etc/ssh/.ssh.db
    rm -rf /etc/bot/.bot.db
    rm -rf /etc/user-create/user.log

    # Buat direktori
    mkdir -p /etc/bot
    mkdir -p /etc/xray
    mkdir -p /etc/vmess
    mkdir -p /etc/vless
    mkdir -p /etc/trojan
    mkdir -p /etc/shadowsocks
    mkdir -p /etc/ssh
    mkdir -p /usr/bin/xray/
    mkdir -p /var/log/xray/
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

    # Set permission
    chmod +x /var/log/xray

    # Buat file penting
    touch /etc/xray/domain
    touch /var/log/xray/access.log
    touch /var/log/xray/error.log
    touch /etc/vmess/.vmess.db
    touch /etc/vless/.vless.db
    touch /etc/trojan/.trojan.db
    touch /etc/shadowsocks/.shadowsocks.db
    touch /etc/ssh/.ssh.db
    touch /etc/bot/.bot.db

    # Inisialisasi database
    echo "& plughin Account" >> /etc/vmess/.vmess.db
    echo "& plughin Account" >> /etc/vless/.vless.db
    echo "& plughin Account" >> /etc/trojan/.trojan.db
    echo "& plughin Account" >> /etc/shadowsocks/.shadowsocks.db
    echo "& plughin Account" >> /etc/ssh/.ssh.db

    echo "echo -e 'Vps Config User Account'" >> /etc/user-create/user.log
}

# ===================================================
# Instal Xray Core dan konfigurasi
# ===================================================
function install_xray() {
    clear
    print_install "Core Xray Latest Version"

    # Buat directory untuk socket Xray
    domainSock_dir="/run/xray"
    ! [ -d $domainSock_dir ] && mkdir $domainSock_dir
    chown www-data.www-data $domainSock_dir

    # Ambil Xray Core Version Terbaru
    latest_version="$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data --version 1.8.23

    # Ambil Config Server
    wget -O /etc/xray/config.json "${REPO}config/config.json" >/dev/null 2>&1
    wget -O /etc/systemd/system/runn.service "${REPO}files/runn.service" >/dev/null 2>&1

    domain=$(cat /etc/xray/domain)
    IPVS=$(cat /etc/xray/ipvps)
    print_success "Core Xray Latest Version"

    # Settings UP Nginx & HAProxy
    clear
    curl -s ipinfo.io/city >> /etc/xray/city
    curl -s ipinfo.io/org | cut -d " " -f 2-10 >> /etc/xray/isp
    print_install "Memasang Konfigurasi Packet"

    wget -O /etc/haproxy/haproxy.cfg "${REPO}config/haproxy.cfg" >/dev/null 2>&1
    wget -O /etc/nginx/conf.d/xray.conf "${REPO}config/xray.conf" >/dev/null 2>&1

    sed -i "s/xxx/${domain}/g" /etc/haproxy/haproxy.cfg
    sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/xray.conf
    curl ${REPO}config/nginx.conf > /etc/nginx/nginx.conf

    # Combine SSL Certificate untuk HAProxy
    cat /etc/xray/xray.crt /etc/xray/xray.key | tee /etc/haproxy/hap.pem

    # Set permission
    chmod +x /etc/systemd/system/runn.service

    # Create Xray service
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

    print_success "Konfigurasi Packet"
}

# ===================================================
# Fungsi SSH & rc.local
# ===================================================
function ssh() {
    clear
    print_install "Memasang Password SSH"

    # Download konfigurasi password
    wget -O /etc/pam.d/common-password "${REPO}files/password"
    chmod +x /etc/pam.d/common-password

    # Konfigurasi keyboard
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

    # Go to root
    cd

    # Buat rc-local.service
    cat > /etc/systemd/system/rc-local.service <<-END
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
END

    # Buat file rc.local
    cat > /etc/rc.local <<-END
#!/bin/sh -e
# rc.local
# By default this script does nothing.
exit 0
END

    # Ubah izin akses
    chmod +x /etc/rc.local

    # Enable rc-local
    systemctl enable rc-local
    systemctl start rc-local.service

    # Disable IPv6
    echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
    sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local

    # Set timezone GMT +7
    ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime

    # Set locale SSH
    sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config

    print_success "Password SSH"
}

# ===================================================
# Fungsi UDP Mini & Limit IP
# ===================================================
function udp_mini() {
    clear
    print_install "Memasang Service Limit IP & Quota"

    wget -q https://raw.githubusercontent.com/welwel11/project2/main/config/fv-tunnel
    chmod +x fv-tunnel
    ./fv-tunnel

    # Pasang UDP Mini
    mkdir -p /usr/local/kyt/
    wget -q -O /usr/local/kyt/udp-mini "${REPO}files/udp-mini"
    chmod +x /usr/local/kyt/udp-mini

    # Pasang systemd service udp-mini-1/2/3
    for i in 1 2 3; do
        wget -q -O /etc/systemd/system/udp-mini-$i.service "${REPO}files/udp-mini-$i.service"
        systemctl disable udp-mini-$i
        systemctl stop udp-mini-$i
        systemctl enable udp-mini-$i
        systemctl start udp-mini-$i
    done

    print_success "Limit IP Service"
}

# ===================================================
# Fungsi SSH SlowDNS
# ===================================================
function ssh_slow() {
    clear
    print_install "Memasang modul SlowDNS Server"

    wget -q -O /tmp/nameserver "${REPO}files/nameserver" >/dev/null 2>&1
    chmod +x /tmp/nameserver
    bash /tmp/nameserver | tee /root/install.log

    print_success "SlowDNS"
}

# ===================================================
# Fungsi Instalasi SSHD
# ===================================================
function ins_SSHD() {
    clear
    print_install "Memasang SSHD"

    wget -q -O /etc/ssh/sshd_config "${REPO}files/sshd" >/dev/null 2>&1
    chmod 700 /etc/ssh/sshd_config

    /etc/init.d/ssh restart
    systemctl restart ssh
    /etc/init.d/ssh status

    print_success "SSHD"
}

# ===================================================
# Fungsi Instalasi Dropbear
# ===================================================
function ins_dropbear() {
    clear
    print_install "Menginstall Dropbear"

    # Install Dropbear
    apt-get install dropbear -y > /dev/null 2>&1
    wget -q -O /etc/default/dropbear "${REPO}config/dropbear.conf"
    chmod +x /etc/default/dropbear

    /etc/init.d/dropbear restart
    /etc/init.d/dropbear status

    print_success "Dropbear"
}

# ===================================================
# Fungsi Instalasi VnStat
# ===================================================
function ins_vnstat() {
    clear
    print_install "Menginstall Vnstat"

    # Install dependencies
    apt -y install vnstat libsqlite3-dev > /dev/null 2>&1
    /etc/init.d/vnstat restart

    # Install vnStat versi 2.6
    wget https://humdi.net/vnstat/vnstat-2.6.tar.gz
    tar zxvf vnstat-2.6.tar.gz
    cd vnstat-2.6
    ./configure --prefix=/usr --sysconfdir=/etc && make && make install
    cd
    rm -f /root/vnstat-2.6.tar.gz
    rm -rf /root/vnstat-2.6

    # Konfigurasi vnStat
    vnstat -u -i $NET
    sed -i 's/Interface "'""eth0""'"/Interface "'""$NET""'"/g' /etc/vnstat.conf
    chown vnstat:vnstat /var/lib/vnstat -R
    systemctl enable vnstat
    /etc/init.d/vnstat restart
    /etc/init.d/vnstat status

    print_success "Vnstat"
}

# ===================================================
# Fungsi Instalasi Backup Server
# ===================================================
function ins_backup() {
    clear
    print_install "Memasang Backup Server"

    # Install rclone
    apt install rclone -y
    printf "q\n" | rclone config
    wget -O /root/.config/rclone/rclone.conf "${REPO}config/rclone.conf"

    # Install Wondershaper
    cd /bin
    git clone https://github.com/magnific0/wondershaper.git
    cd wondershaper
    sudo make install
    cd
    rm -rf wondershaper

    echo > /home/limit

    # Install mail utilities
    apt install msmtp-mta ca-certificates bsd-mailx -y

    cat <<EOF >> /etc/msmtprc
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

    wget -q -O /etc/ipserver "${REPO}files/ipserver" && bash /etc/ipserver

    print_success "Backup Server"
}

# ===================================================
# Fungsi Instalasi Swap 1G & BBR
# ===================================================
function ins_swab() {
    clear
    print_install "Memasang Swap 1 G"

    # Install Gotop (opsional monitoring)
    gotop_latest="$(curl -s https://api.github.com/repos/xxxserxxx/gotop/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
    gotop_link="https://github.com/xxxserxxx/gotop/releases/download/v$gotop_latest/gotop_v${gotop_latest}_linux_amd64.deb"
    curl -sL "$gotop_link" -o /tmp/gotop.deb
    dpkg -i /tmp/gotop.deb >/dev/null 2>&1

    # Buat swap sebesar 1G
    dd if=/dev/zero of=/swapfile bs=1024 count=1048576
    mkswap /swapfile
    chown root:root /swapfile
    chmod 0600 /swapfile >/dev/null 2>&1
    swapon /swapfile >/dev/null 2>&1
    sed -i '$ i\/swapfile      swap swap   defaults    0 0' /etc/fstab

    # Sinkronisasi jam
    chronyd -q 'server 0.id.pool.ntp.org iburst'
    chronyc sourcestats -v
    chronyc tracking -v

    # Install BBR
    wget ${REPO}files/bbr.sh && chmod +x bbr.sh && ./bbr.sh

    print_success "Swap 1 G"
}

# ===================================================
# Fungsi Instalasi Fail2Ban dan Banner
# ===================================================
function ins_Fail2ban() {
    clear
    print_install "Menginstall Fail2ban"

    # Uncomment jika ingin install fail2ban otomatis
    # apt -y install fail2ban > /dev/null 2>&1
    # sudo systemctl enable --now fail2ban
    # /etc/init.d/fail2ban restart
    # /etc/init.d/fail2ban status

    clear
    # Setting banner untuk SSH dan Dropbear
    echo "Banner /etc/kyt.txt" >> /etc/ssh/sshd_config
    sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/kyt.txt"@g' /etc/default/dropbear

    # Download banner custom
    wget -O /etc/kyt.txt "${REPO}files/issue.net"

    print_success "Fail2ban"
}

# ===================================================
# Fungsi Instalasi ePro WebSocket Proxy
# ===================================================
function ins_epro() {
    clear
    print_install "Menginstall ePro WebSocket Proxy"

    # Download file dan service
    wget -O /usr/bin/ws "${REPO}files/ws" >/dev/null 2>&1
    wget -O /usr/bin/tun.conf "${REPO}config/tun.conf" >/dev/null 2>&1
    wget -O /etc/systemd/system/ws.service "${REPO}files/ws.service" >/dev/null 2>&1

    chmod +x /usr/bin/ws
    chmod 644 /usr/bin/tun.conf
    chmod +x /etc/systemd/system/ws.service

    systemctl disable ws
    systemctl stop ws
    systemctl enable ws
    systemctl start ws
    systemctl restart ws

    # Download geosite.dat & geoip.dat
    wget -q -O /usr/local/share/xray/geosite.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat" >/dev/null 2>&1
    wget -q -O /usr/local/share/xray/geoip.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat" >/dev/null 2>&1

    # Install ftvpn
    wget -O /usr/sbin/ftvpn "${REPO}files/ftvpn" >/dev/null 2>&1
    chmod +x /usr/sbin/ftvpn

    # Aturan iptables untuk blokir torrent
    iptables -A FORWARD -m string --string "get_peers" --algo bm -j DROP
    iptables -A FORWARD -m string --string "announce_peer" --algo bm -j DROP
    iptables -A FORWARD -m string --string "find_node" --algo bm -j DROP
    iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP
    iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP
    iptables -A FORWARD -m string --algo bm --string "peer_id=" -j DROP
    iptables -A FORWARD -m string --algo bm --string ".torrent" -j DROP
    iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP
    iptables -A FORWARD -m string --algo bm --string "torrent" -j DROP
    iptables -A FORWARD -m string --algo bm --string "announce" -j DROP
    iptables -A FORWARD -m string --algo bm --string "info_hash" -j DROP
    iptables-save > /etc/iptables.up.rules
    iptables-restore -t < /etc/iptables.up.rules
    netfilter-persistent save
    netfilter-persistent reload

    # Bersihkan file yang tidak perlu
    cd
    apt autoclean -y >/dev/null 2>&1
    apt autoremove -y >/dev/null 2>&1

    print_success "ePro WebSocket Proxy"
}

# ===================================================
# Fungsi Restart Semua Service
# ===================================================
function ins_restart() {
    clear
    print_install "Restarting All Packet"

    # Restart service
    /etc/init.d/nginx restart
    /etc/init.d/ssh restart
    /etc/init.d/dropbear restart
    /etc/init.d/fail2ban restart
    /etc/init.d/vnstat restart
    systemctl restart haproxy
    /etc/init.d/cron restart

    # Enable & start service
    systemctl daemon-reload
    systemctl start netfilter-persistent
    systemctl enable --now nginx
    systemctl enable --now xray
    systemctl enable --now rc-local
    systemctl enable --now dropbear
    systemctl enable --now cron
    systemctl enable --now haproxy
    systemctl enable --now netfilter-persistent
    systemctl enable --now ws
    systemctl enable --now fail2ban

    # Bersihkan history
    history -c
    echo "unset HISTFILE" >> /etc/profile

    # Hapus file key/cert sementara
    cd
    rm -f /root/key.pem
    rm -f /root/cert.pem

    print_success "All Packet"
}

# ===================================================
# Instal Menu Packet
# ===================================================
function menu(){
    clear
    print_install "Memasang Menu Packet"
    wget ${REPO}menu/menu.zip
    unzip menu.zip
    chmod +x menu/*
    mv menu/* /usr/local/sbin
    rm -rf menu
    rm -rf menu.zip
}

# ===================================================
# Membuat Default Profile dan Cron Jobs
# ===================================================
function profile(){
    clear
    # Set default shell profile
    cat >/root/.profile <<EOF
# ~/.profile: executed by Bourne-compatible login shells.
if [ "\$BASH" ]; then
    if [ -f ~/.bashrc ]; then
        . ~/.bashrc
    fi
fi
mesg n || true
menu
EOF

    # Cron jobs setup
    cat >/etc/cron.d/xp_all <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
2 0 * * * root /usr/local/sbin/xp
END

    cat >/etc/cron.d/logclean <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/20 * * * * root /usr/local/sbin/clearlog
END

    cat >/etc/cron.d/daily_reboot <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 3 * * * root /sbin/reboot
END

    cat >/etc/cron.d/limit_ip <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/2 * * * * root /usr/local/sbin/limit-ip
END

    cat >/etc/cron.d/limit_ip2 <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/2 * * * * root /usr/bin/limit-ip
END

    echo "*/1 * * * * root echo -n > /var/log/nginx/access.log" >/etc/cron.d/log.nginx
    echo "*/1 * * * * root echo -n > /var/log/xray/access.log" >>/etc/cron.d/log.xray

    service cron restart

    cat >/home/daily_reboot <<-END
5
END

    # Setup rc-local service
    cat >/etc/systemd/system/rc-local.service <<EOF
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

    # Setup rc.local script
    cat >/etc/rc.local <<EOF
#!/bin/sh -e
# rc.local
iptables -I INPUT -p udp --dport 5300 -j ACCEPT
iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300
systemctl restart netfilter-persistent
exit 0
EOF

    chmod +x /etc/rc.local

    # Add shells
    echo "/bin/false" >>/etc/shells
    echo "/usr/sbin/nologin" >>/etc/shells

    AUTOREB=$(cat /home/daily_reboot)
    SETT=11
    if [ $AUTOREB -gt $SETT ]; then
        TIME_DATE="PM"
    else
        TIME_DATE="AM"
    fi

    print_success "Menu Packet"
}

# ===================================================
# Enable Semua Service
# ===================================================
function enable_services(){
    clear
    print_install "Enable Service"
    systemctl daemon-reload
    systemctl start netfilter-persistent
    systemctl enable --now rc-local
    systemctl enable --now cron
    systemctl enable --now netfilter-persistent
    systemctl restart nginx
    systemctl restart xray
    systemctl restart cron
    systemctl restart haproxy
    print_success "Enable Service"
    clear
}

# ===================================================
# Fungsi Instalasi Utama
# ===================================================
function instal(){
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

# ===================================================
# Jalankan Instalasi
# ===================================================
instal

# Bersihkan file & history
echo ""
history -c
rm -rf /root/menu
rm -rf /root/*.zip
rm -rf /root/*.sh
rm -rf /root/LICENSE
rm -rf /root/README.md
rm -rf /root/domain

# Set hostname & waktu eksekusi
secs_to_human "$(($(date +%s) - ${start}))"
sudo hostnamectl set-hostname $username

echo -e "${green} Script Successfully Installed"
echo ""
read -p "$( echo -e "Press ${YELLOW}[ ${NC}${YELLOW}Enter${NC} ${YELLOW}]${NC} For reboot") "
reboot
