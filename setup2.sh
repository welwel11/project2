#!/bin/bash

# ==== COLORS (PASTIKAN KONSISTEN) ====
RED="\e[1;31m"
GREEN="\e[0;32m"
YELLOW="\033[33m"
BLUE="\033[36m"
GRAY="\e[1;30m"
NC="\e[0m"
FONT="\e[0m"

OK="${GREEN}✔${NC}"
ERROR="${RED}[ERROR]${NC}"

# ==== IP FIX (SATU SUMBER SAJA) ====
MYIP="$IP"

echo -e "${GREEN}loading...${NC}"
sleep 1
clear

# ==== REPO ====
REPO="https://raw.githubusercontent.com/welwel11/project2/main/"

# ==== TIMER ====
start=$(date +%s)
secs_to_human() {
    echo "Installation time : $(( $1 / 3600 )) hours $(( ($1 / 60) % 60 )) minutes $(( $1 % 60 )) seconds"
}

# ==== STATUS FUNCTIONS ====
print_ok() {
    echo -e "${OK} ${BLUE}$1${NC}"
}

print_install() {
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}» $1${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    sleep 1
}

print_error() {
    echo -e "${ERROR} $1"
}

print_success() {
    echo -e "${GREEN}✔ $1 berhasil dipasang${NC}"
    sleep 1
}

# ==== XRAY DIRECTORY ====
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

# ==== RAM INFORMATION ====
mem_used=0
mem_total=0
while IFS=":" read -r a b; do
    case $a in
        MemTotal) mem_total=${b/kB} ;;
        Shmem) ((mem_used+=${b/kB})) ;;
        MemFree|Buffers|Cached|SReclaimable)
            ((mem_used-=${b/kB}))
        ;;
    esac
done < /proc/meminfo

Ram_Usage=$((mem_used / 1024))
Ram_Total=$((mem_total / 1024))

# ==== SYSTEM INFO ====
export tanggal="$(date +"%d-%m-%Y - %X")"
. /etc/os-release
export OS_Name="$PRETTY_NAME"
export Kernel="$(uname -r)"
export Arch="$(uname -m)"

# ==== FIRST SETUP ====
first_setup() {
    timedatectl set-timezone Asia/Jakarta

    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections

    if [[ "$ID" == "ubuntu" ]]; then
        echo "Setup Dependencies for $PRETTY_NAME"
        apt update -y
        apt install -y --no-install-recommends software-properties-common
        apt install -y haproxy

    elif [[ "$ID" == "debian" ]]; then
        echo "Setup Dependencies for $PRETTY_NAME"

        curl -fsSL https://haproxy.debian.net/bernat.debian.org.gpg \
        | gpg --dearmor -o /usr/share/keyrings/haproxy.gpg

        echo "deb [signed-by=/usr/share/keyrings/haproxy.gpg] \
http://haproxy.debian.net ${VERSION_CODENAME}-backports-2.2 main" \
        > /etc/apt/sources.list.d/haproxy.list

        apt update -y
        apt install -y haproxy

    else
        echo "OS Not Supported: $PRETTY_NAME"
        exit 1
    fi
}

# ==== INSTALL NGINX ====
nginx_install() {
    if [[ "$ID" == "ubuntu" || "$ID" == "debian" ]]; then
        echo "Installing nginx for $PRETTY_NAME"
        apt install -y nginx
    else
        echo "OS Not Supported: $PRETTY_NAME"
    fi
}

# ==== BASE PACKAGE ====
base_package() {
    apt update -y
    apt upgrade -y
    apt dist-upgrade -y

    apt install -y \
        zip pwgen openssl netcat socat cron bash-completion figlet \
        sudo debconf-utils ntpdate \
        software-properties-common \
        speedtest-cli vnstat \
        libnss3-dev libnspr4-dev pkg-config libpam0g-dev libcap-ng-dev \
        libcap-ng-utils libselinux1-dev libcurl4-nss-dev flex bison \
        make libnss3-tools libevent-dev bc rsyslog dos2unix zlib1g-dev \
        libssl-dev libsqlite3-dev sed dirmngr libxml-parser-perl \
        build-essential gcc g++ python htop lsof tar wget curl ruby \
        zip unzip p7zip-full python3-pip libc6 util-linux \
        msmtp-mta ca-certificates bsd-mailx \
        iptables iptables-persistent netfilter-persistent net-tools \
        gnupg gnupg2 lsb-release shc cmake git screen socat xz-utils \
        apt-transport-https gnupg1 dnsutils jq openvpn easy-rsa \
        chrony

    # === TIME SYNC (FIX UBUNTU 20.04) ===
    systemctl stop systemd-timesyncd >/dev/null 2>&1
    systemctl disable systemd-timesyncd >/dev/null 2>&1

    systemctl enable chrony
    systemctl restart chrony
    chronyc tracking

    # === NTP MANUAL SYNC (OPTIONAL) ===
    ntpdate pool.ntp.org || true

    # === CLEANUP ===
    apt-get clean all
    apt-get autoremove -y

    # === REMOVE UNNEEDED SERVICES ===
    apt-get remove --purge -y exim4 ufw firewalld

    # === IPTABLES AUTO SAVE ===
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections

    print_success "Packet Yang Dibutuhkan"
}
clear
# ===== FUNGSI SETUP DOMAIN =====
pasang_domain() {
    clear
    echo -e "${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}"
    echo -e "${YELLOW}» SETUP DOMAIN CLOUDFLARE ${FONT}"
    echo -e "${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}"
    echo -e "  [1] Domain Pribadi"
    echo -e "  [2] Domain Bawaan"
    echo -e "${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}"

    read -p "  Silahkan Pilih Menu Domain 1 or 2 (enter) : " host
    echo ""

    if [[ "$host" == "1" ]]; then
        echo -e "   \e[1;32mMasukan Domain Anda ! ${NC}"
        read -p "   Subdomain: " host1

        mkdir -p /var/lib/kyt
        echo "IP=" > /var/lib/kyt/ipvps.conf
        echo "$host1" > /etc/xray/domain
        echo "$host1" > /root/domain

    elif [[ "$host" == "2" ]]; then
        wget -q -O /root/cf.sh "${REPO}files/cf.sh"
        chmod +x /root/cf.sh
        /root/cf.sh
        rm -f /root/cf.sh
        clear
    else
        print_install "Random Subdomain / Domain Digunakan"
        clear
    fi
}

# ===== CEK LICENSE =====
restart_system() {
    MYIP=$(curl -s ipv4.icanhazip.com)
    izinsc="https://raw.githubusercontent.com/welwel11/izin/main/izin"

    username=$(curl -s "$izinsc" | grep "$MYIP" | awk '{print $2}')
    exp=$(curl -s "$izinsc" | grep "$MYIP" | awk '{print $3}')

    if [[ -z "$username" || -z "$exp" ]]; then
        echo -e "\e[31mLicense Not Found\e[0m"
        exit 1
    fi

    echo "$username" > /usr/bin/user
    echo "$exp" > /usr/bin/e

    today=$(date +"%Y-%m-%d")
    d1=$(date -d "$exp" +%s 2>/dev/null)
    d2=$(date -d "$today" +%s)

    if [[ -z "$d1" ]]; then
        echo -e "\e[31mLicense Expired / Invalid Date\e[0m"
        exit 1
    fi

    certifacate=$(((d1 - d2) / 86400))
    echo -e "Expiry In   : ${certifacate} Days"
}

# ===== PASANG SSL =====
pasang_ssl() {
    clear
    print_install "Memasang SSL Pada Domain"
    rm -rf /etc/xray/xray.key
    rm -rf /etc/xray/xray.crt
    domain=$(cat /root/domain)
    STOPWEBSERVER=$(lsof -i:80 | cut -d' ' -f1 | awk 'NR==2 {print $1}')
    rm -rf /root/.acme.sh
    mkdir /root/.acme.sh
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

# ===== BUAT FOLDER XRAY =====
make_folder_xray() {
rm -rf /etc/vmess/.vmess.db
    rm -rf /etc/vless/.vless.db
    rm -rf /etc/trojan/.trojan.db
    rm -rf /etc/shadowsocks/.shadowsocks.db
    rm -rf /etc/ssh/.ssh.db
    rm -rf /etc/bot/.bot.db
    rm -rf /etc/user-create/user.log
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
    chmod +x /var/log/xray
    touch /etc/xray/domain
    touch /var/log/xray/access.log
    touch /var/log/xray/error.log
    touch /etc/vmess/.vmess.db
    touch /etc/vless/.vless.db
    touch /etc/trojan/.trojan.db
    touch /etc/shadowsocks/.shadowsocks.db
    touch /etc/ssh/.ssh.db
    touch /etc/bot/.bot.db
    echo "& plughin Account" >>/etc/vmess/.vmess.db
    echo "& plughin Account" >>/etc/vless/.vless.db
    echo "& plughin Account" >>/etc/trojan/.trojan.db
    echo "& plughin Account" >>/etc/shadowsocks/.shadowsocks.db
    echo "& plughin Account" >>/etc/ssh/.ssh.db
    echo "echo -e 'Vps Config User Account'" >> /etc/user-create/user.log
    }

# ===== INSTALL XRAY =====
install_xray() {
    clear
    print_install "Core Xray Latest Version"

    domainSock_dir="/run/xray"
    mkdir -p "$domainSock_dir"
    chown www-data:www-data "$domainSock_dir"

    bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" \
        @ install -u www-data

    wget -O /etc/xray/config.json "${REPO}config/config.json" >/dev/null 2>&1
    wget -O /etc/systemd/system/runn.service "${REPO}files/runn.service" >/dev/null 2>&1

    domain=$(cat /etc/xray/domain)

    print_success "Core Xray"

    curl -s ipinfo.io/city >>/etc/xray/city
    curl -s ipinfo.io/org | cut -d " " -f 2-10 >>/etc/xray/isp

    wget -O /etc/haproxy/haproxy.cfg "${REPO}config/haproxy.cfg" >/dev/null 2>&1
    wget -O /etc/nginx/conf.d/xray.conf "${REPO}config/xray.conf" >/dev/null 2>&1
    sed -i "s/xxx/${domain}/g" /etc/haproxy/haproxy.cfg
    sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/xray.conf
    curl ${REPO}config/nginx.conf > /etc/nginx/nginx.conf
    
cat /etc/xray/xray.crt /etc/xray/xray.key | tee /etc/haproxy/hap.pem

    chmod +x /etc/systemd/system/runn.service
    
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

# ===== SSH CONFIG (RENAME) =====
ssh_config() {
    clear
wget -O /etc/pam.d/common-password "${REPO}files/password"
chmod +x /etc/pam.d/common-password

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

# go to root
cd

# Edit file /etc/systemd/system/rc-local.service
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

# Ubah izin akses
chmod +x /etc/rc.local

# enable rc local
systemctl enable rc-local
systemctl start rc-local.service

# disable ipv6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local

#update
# set time GMT +7
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime

# set locale
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
print_success "Password SSH"
}

# ===== LIMIT IP =====
limit_ip() {
    clear
    print_install "Memasang Service Limit IP & Quota"
    
wget -q https://raw.githubusercontent.com/welwel11/project2/main/config/fv-tunnel && chmod +x fv-tunnel && ./fv-tunnel
    print_success "Limit IP Service"
}

# ===== SSHD =====
ins_SSHD() {
    clear
wget -q -O /etc/ssh/sshd_config "${REPO}files/sshd" >/dev/null 2>&1
chmod 700 /etc/ssh/sshd_config
/etc/init.d/ssh restart
systemctl restart ssh
/etc/init.d/ssh status
print_success "SSHD"
}

# ===== DROPBEAR =====
ins_dropbear() {
    clear
    print_install "Menginstall Dropbear"
apt-get install dropbear -y > /dev/null 2>&1
wget -q -O /etc/default/dropbear "${REPO}config/dropbear.conf"
chmod +x /etc/default/dropbear
/etc/init.d/dropbear restart
/etc/init.d/dropbear status
print_success "Dropbear"
}

# ===== VNSTAT =====
ins_vnstat() {
    clear
    print_install "Menginstall Vnstat"
apt -y install vnstat > /dev/null 2>&1
/etc/init.d/vnstat restart
apt -y install libsqlite3-dev > /dev/null 2>&1
wget https://humdi.net/vnstat/vnstat-2.6.tar.gz
tar zxvf vnstat-2.6.tar.gz
cd vnstat-2.6
./configure --prefix=/usr --sysconfdir=/etc && make && make install
cd
vnstat -u -i $NET
sed -i 's/Interface "'""eth0""'"/Interface "'""$NET""'"/g' /etc/vnstat.conf
chown vnstat:vnstat /var/lib/vnstat -R
systemctl enable vnstat
/etc/init.d/vnstat restart
/etc/init.d/vnstat status
rm -f /root/vnstat-2.6.tar.gz
rm -rf /root/vnstat-2.6
print_success "Vnstat"
}

# ===== BACKUP SERVER =====
ins_backup() {
    clear
    print_install "Memasang Backup Server"

    apt install -y rclone msmtp-mta ca-certificates bsd-mailx

    mkdir -p /root/.config/rclone
    printf "q\n" | rclone config
    wget -q -O /root/.config/rclone/rclone.conf "${REPO}config/rclone.conf"

    cd /tmp || exit
    git clone https://github.com/magnific0/wondershaper.git
    cd wondershaper || exit
    make install
    cd
    rm -rf /tmp/wondershaper

    touch /home/limit
    chmod 644 /home/limit

    cat <<EOF > /etc/msmtprc
defaults
tls on
tls_starttls on
tls_trust_file /etc/ssl/certs/ca-certificates.crt

account default
host smtp.gmail.com
port 587
auth on
user ISI_EMAIL_ANDA
from ISI_EMAIL_ANDA
password ISI_PASSWORD_ANDA
logfile ~/.msmtp.log
EOF

    chmod 600 /etc/msmtprc

    wget -q -O /etc/ipserver "${REPO}files/ipserver"
    bash /etc/ipserver

    print_success "Backup Server"
}

# ===== SWAP =====
ins_swab() {
    clear
    print_install "Memasang Swap 1 G"

    if ! swapon --show | grep -q swapfile; then
        dd if=/dev/zero of=/swapfile bs=1M count=1024
        chmod 600 /swapfile
        mkswap /swapfile
        swapon /swapfile
        grep -q swapfile /etc/fstab || echo "/swapfile swap swap defaults 0 0" >> /etc/fstab
    fi

    apt install -y chrony
    chronyc tracking

    wget -q -O /root/bbr.sh "${REPO}files/bbr.sh"
    chmod +x /root/bbr.sh
    /root/bbr.sh

    print_success "Swap 1 G"
}

# ===== FAIL2BAN =====
ins_Fail2ban() {
    clear
    print_install "Menginstall Fail2ban"
apt -y install fail2ban > /dev/null 2>&1
sudo systemctl enable --now fail2ban
/etc/init.d/fail2ban restart
/etc/init.d/fail2ban status

clear
# banner
echo "Banner /etc/kyt.txt" >>/etc/ssh/sshd_config
sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/kyt.txt"@g' /etc/default/dropbear

# Ganti Banner
wget -O /etc/kyt.txt "${REPO}files/issue.net"
print_success "Fail2ban"
}

# ===== EPRO =====
ins_epro() {
    clear
    print_install "Menginstall ePro WebSocket Proxy"

    mkdir -p /usr/local/share/xray

    wget -q -O /usr/bin/ws "${REPO}files/ws"
    wget -q -O /usr/bin/tun.conf "${REPO}config/tun.conf"
    wget -q -O /etc/systemd/system/ws.service "${REPO}files/ws.service"

    chmod +x /usr/bin/ws
    chmod 644 /usr/bin/tun.conf
    chmod 644 /etc/systemd/system/ws.service

    systemctl daemon-reexec
    systemctl enable --now ws

    wget -q -O /usr/local/share/xray/geosite.dat \
      "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"
    wget -q -O /usr/local/share/xray/geoip.dat \
      "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"

    wget -q -O /usr/sbin/ftvpn "${REPO}files/ftvpn"
    chmod +x /usr/sbin/ftvpn

    netfilter-persistent save
    netfilter-persistent reload

    apt autoremove -y
    apt autoclean -y

    print_success "ePro WebSocket Proxy"
}

# ===== ANTI DDOS BASIC =====
anti_ddos_basic() {
    clear
    print_install "Mengaktifkan Anti DDOS Basic Protection"

    # Allow loopback
    iptables -C INPUT -i lo -j ACCEPT 2>/dev/null || \
    iptables -A INPUT -i lo -j ACCEPT

    # Allow established connections
    iptables -C INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # Drop invalid packets
    iptables -C INPUT -m conntrack --ctstate INVALID -j DROP 2>/dev/null || \
    iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

    # SYN flood protection
    iptables -C INPUT -p tcp --syn -m limit --limit 2/s --limit-burst 10 -j ACCEPT 2>/dev/null || \
    iptables -A INPUT -p tcp --syn -m limit --limit 2/s --limit-burst 10 -j ACCEPT

    iptables -C INPUT -p tcp --syn -j DROP 2>/dev/null || \
    iptables -A INPUT -p tcp --syn -j DROP

    netfilter-persistent save
    netfilter-persistent reload

    sysctl -w net.ipv4.tcp_syncookies=1 >/dev/null

    print_success "Anti DDOS Basic"
}

# ===== RESTART SERVICE =====
ins_restart() {
    clear
    print_install "Restarting All Packet"

    systemctl daemon-reload

    for svc in nginx ssh dropbear fail2ban vnstat cron haproxy netfilter-persistent ws xray; do
        systemctl restart "$svc" 2>/dev/null
        systemctl enable "$svc" 2>/dev/null
    done

    history -c
    sed -i '/HISTFILE/d' /etc/profile
    echo "unset HISTFILE" >> /etc/profile

    rm -f /root/key.pem /root/cert.pem

    print_success "All Packet"
}

# ===== INSTALL MENU =====
menu() {
    clear
    print_install "Memasang Menu Packet"

    apt install -y unzip >/dev/null 2>&1
    cd /tmp || exit
    wget -q "${REPO}menu/menu.zip"
    unzip -o menu.zip
    chmod +x menu/*
    mv menu/* /usr/local/sbin
    rm -rf menu menu.zip

    print_success "Menu Packet"
}

# ===== PROFILE & CRON =====
profile() {
    clear

cat >/root/.profile <<'EOF'
if [ "$BASH" ]; then
    [ -f ~/.bashrc ] && . ~/.bashrc
fi
mesg n || true
command -v menu >/dev/null 2>&1 && menu
EOF
chmod 644 /root/.profile

cat >/etc/cron.d/xp_all <<'EOF'
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
2 0 * * * root /usr/local/sbin/xp
EOF

cat >/etc/cron.d/logclean <<'EOF'
*/30 * * * * root /usr/local/sbin/clearlog
EOF

cat >/etc/cron.d/daily_reboot <<'EOF'
0 3 * * * root /sbin/reboot
EOF

cat >/etc/cron.d/limit_ip <<'EOF'
*/2 * * * * root /usr/local/sbin/limit-ip
EOF

cat >/etc/cron.d/log_nginx <<'EOF'
*/5 * * * * root truncate -s 0 /var/log/nginx/access.log
EOF

cat >/etc/cron.d/log_xray <<'EOF'
*/5 * * * * root truncate -s 0 /var/log/xray/access.log
EOF

systemctl restart cron

# rc.local
cat >/etc/rc.local <<'EOF'
#!/bin/sh -e
iptables -C INPUT -p udp --dport 5300 -j ACCEPT 2>/dev/null || \
iptables -I INPUT -p udp --dport 5300 -j ACCEPT
iptables -t nat -C PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300 2>/dev/null || \
iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300
exit 0
EOF

chmod +x /etc/rc.local
systemctl enable rc-local

print_success "Menu Packet"
}

# ===== ENABLE SERVICES =====
enable_services(){
    clear
    print_install "Enable Service"

    systemctl daemon-reload

    for svc in cron nginx haproxy netfilter-persistent rc-local xray; do
        systemctl enable "$svc" 2>/dev/null
        systemctl restart "$svc" 2>/dev/null
    done

    print_success "Enable Service"
}

# ===== INSTALL ALL =====
instal(){
set -e
    clear

    restart_system
    first_setup
    nginx_install
    base_package
    make_folder_xray
    pasang_domain
    pasang_ssl
    install_xray
    ssh_config
    limit_ip
    ins_SSHD
    ins_dropbear
    ins_vnstat
    ins_backup
    ins_swab
    ins_Fail2ban
    ins_epro
    anti_ddos_basic
    ins_restart
    menu
    profile
    enable_services
}

instal

history -c

rm -rf /root/menu /root/*.zip /root/LICENSE /root/README.md /root/domain

[ -n "$username" ] && hostnamectl set-hostname "$username"

secs_to_human "$(($(date +%s) - ${start}))"

echo -e "${green} Script Successfully Installed"
echo ""
read -p "Press ENTER to reboot"
reboot