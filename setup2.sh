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
mkdir -p /etc/xray /var/log/xray /var/lib/kyt
curl -s ifconfig.me > /etc/xray/ipvps
touch /etc/xray/domain
touch /var/log/xray/access.log /var/log/xray/error.log
chown www-data:www-data /var/log/xray
chmod 755 /var/log/xray

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
        ntpdate chrony sudo debconf-utils \
        speedtest-cli vnstat jq \
        curl wget lsof tar zip unzip p7zip-full \
        python3 python3-pip ruby \
        git screen socat dnsutils \
        build-essential make cmake gcc g++ \
        iptables iptables-persistent netfilter-persistent \
        openvpn easy-rsa msmtp-mta bsd-mailx

    systemctl enable chrony
    systemctl restart chrony

    ntpdate pool.ntp.org

    apt remove --purge -y exim4 ufw firewalld
    apt autoremove -y
    apt clean
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

    domain=$(cat /root/domain)
    rm -rf /etc/xray/xray.key /etc/xray/xray.crt
    rm -rf /root/.acme.sh

    systemctl stop nginx 2>/dev/null

    mkdir -p /root/.acme.sh
    curl -fsSL https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
    chmod +x /root/.acme.sh/acme.sh

    /root/.acme.sh/acme.sh --upgrade --auto-upgrade
    /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
    /root/.acme.sh/acme.sh --issue -d "$domain" --standalone -k ec-256
    /root/.acme.sh/acme.sh --installcert -d "$domain" \
        --fullchainpath /etc/xray/xray.crt \
        --keypath /etc/xray/xray.key --ecc

    chmod 600 /etc/xray/xray.key
    print_success "SSL Certificate"
}

# ===== BUAT FOLDER XRAY =====
make_folder_xray() {
    mkdir -p \
        /etc/xray /etc/vmess /etc/vless /etc/trojan /etc/shadowsocks /etc/ssh /etc/bot \
        /etc/user-create \
        /etc/kyt/limit/{vmess,vless,trojan,ssh}/ip \
        /etc/limit/{vmess,vless,trojan,ssh} \
        /usr/bin/xray \
        /var/log/xray \
        /var/www/html

    touch \
        /etc/xray/domain \
        /var/log/xray/access.log \
        /var/log/xray/error.log \
        /etc/vmess/.vmess.db \
        /etc/vless/.vless.db \
        /etc/trojan/.trojan.db \
        /etc/shadowsocks/.shadowsocks.db \
        /etc/ssh/.ssh.db \
        /etc/bot/.bot.db \
        /etc/user-create/user.log

    chmod 755 /var/log/xray

    echo "& plugin Account" >> /etc/vmess/.vmess.db
    echo "& plugin Account" >> /etc/vless/.vless.db
    echo "& plugin Account" >> /etc/trojan/.trojan.db
    echo "& plugin Account" >> /etc/shadowsocks/.shadowsocks.db
    echo "& plugin Account" >> /etc/ssh/.ssh.db
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

    wget -q -O /etc/xray/config.json "${REPO}config/config.json"
    wget -q -O /etc/systemd/system/runn.service "${REPO}files/runn.service"

    domain=$(cat /etc/xray/domain 2>/dev/null)

    print_success "Core Xray"

    curl -s ipinfo.io/city > /etc/xray/city
    curl -s ipinfo.io/org | cut -d " " -f 2-10 > /etc/xray/isp

    print_install "Memasang Konfigurasi Packet"
    wget -q -O /etc/haproxy/haproxy.cfg "${REPO}config/haproxy.cfg"
    wget -q -O /etc/nginx/conf.d/xray.conf "${REPO}config/xray.conf"
    sed -i "s/xxx/${domain}/g" /etc/haproxy/haproxy.cfg
    sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/xray.conf
    curl -fsSL "${REPO}config/nginx.conf" > /etc/nginx/nginx.conf

    cat /etc/xray/xray.crt /etc/xray/xray.key > /etc/haproxy/hap.pem
    chmod 600 /etc/haproxy/hap.pem

    chmod 644 /etc/systemd/system/runn.service
    print_success "Konfigurasi Packet"
}

# ===== SSH CONFIG (RENAME) =====
ssh_config() {
    clear
    print_install "Konfigurasi SSH"

    wget -q -O /etc/pam.d/common-password "${REPO}files/password"
    chmod 644 /etc/pam.d/common-password

    sed -i 's/^AcceptEnv/#AcceptEnv/' /etc/ssh/sshd_config

    sysctl -w net.ipv6.conf.all.disable_ipv6=1
    echo "net.ipv6.conf.all.disable_ipv6=1" > /etc/sysctl.d/99-disable-ipv6.conf
    sysctl --system

    ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
    print_success "SSH Config"
}

# ===== UDP MINI =====
udp_mini() {
    clear
    print_install "Memasang Service Limit IP & Quota"

    wget -q -O /tmp/fv-tunnel https://raw.githubusercontent.com/welwel11/project2/main/config/fv-tunnel
    chmod +x /tmp/fv-tunnel
    /tmp/fv-tunnel

    mkdir -p /usr/local/kyt
    wget -q -O /usr/local/kyt/udp-mini "${REPO}files/udp-mini"
    chmod +x /usr/local/kyt/udp-mini

    for i in 1 2 3; do
        wget -q -O /etc/systemd/system/udp-mini-$i.service "${REPO}files/udp-mini-$i.service"
        systemctl enable udp-mini-$i
        systemctl restart udp-mini-$i
    done

    print_success "Limit IP Service"
}

# ===== SLOWDNS =====
#ssh_slow() {
#    clear
#    print_install "Memasang modul SlowDNS Server"
#    wget -q -O /tmp/nameserver "${REPO}files/nameserver"
#    chmod +x /tmp/nameserver
#    /tmp/nameserver | tee /root/install.log
#    rm -f /tmp/nameserver
#    print_success "SlowDNS"
#}

# ===== SSHD =====
ins_SSHD() {
    clear
    print_install "Memasang SSHD"
    wget -q -O /etc/ssh/sshd_config "${REPO}files/sshd"
    chmod 600 /etc/ssh/sshd_config
    systemctl restart ssh
    systemctl status ssh --no-pager
    print_success "SSHD"
}

# ===== DROPBEAR =====
ins_dropbear() {
    clear
    print_install "Menginstall Dropbear"
    apt-get install -y dropbear >/dev/null 2>&1
    wget -q -O /etc/default/dropbear "${REPO}config/dropbear.conf"
    chmod 644 /etc/default/dropbear
    systemctl restart dropbear
    systemctl status dropbear --no-pager
    print_success "Dropbear"
}

# ===== VNSTAT =====
ins_vnstat() {
    clear
    print_install "Menginstall Vnstat"
    apt install -y vnstat
    NET=$(ip route | awk '/default/ {print $5}')
    vnstat -u -i "$NET"
    chown -R vnstat:vnstat /var/lib/vnstat
    systemctl enable vnstat
    systemctl restart vnstat
    systemctl status vnstat --no-pager
    print_success "Vnstat"
}

# ===== OPENVPN =====
ins_openvpn() {
    clear
    print_install "Menginstall OpenVPN"
    wget -q -O /root/openvpn-install.sh "${REPO}files/openvpn"
    chmod +x /root/openvpn-install.sh
    /root/openvpn-install.sh
    systemctl restart openvpn
    print_success "OpenVPN"
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

    apt install -y fail2ban
    systemctl enable --now fail2ban

    grep -q "^Banner /etc/kyt.txt" /etc/ssh/sshd_config || \
        echo "Banner /etc/kyt.txt" >> /etc/ssh/sshd_config

    sed -i 's@^DROPBEAR_BANNER=.*@DROPBEAR_BANNER="/etc/kyt.txt"@' /etc/default/dropbear

    wget -q -O /etc/kyt.txt "${REPO}files/issue.net"

    systemctl restart ssh
    systemctl restart dropbear

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
    udp_mini
    ssh_slow
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