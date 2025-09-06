#!/bin/bash
#=================================================
# Quick VPN/Xray Server Installer Ubuntu 24
# Support: SSHWS, HAProxy, Vmess, Vless, Trojan, UDP Mini, SlowDNS, Dropbear, vnStat, Backup, Fail2ban, ePro
# Author:  / Github https://github.com/welwel11/project2
#=================================================

Green="\e[92;1m"
RED="\033[31m"
YELLOW="\033[33m"
BLUE="\033[36m"
FONT="\033[0m"
OK="${Green}  »${FONT}"
ERROR="${RED}[ERROR]${FONT}"
NC='\e[0m'

# Clear screen
clear

# Get IP
export IP=$(curl -sS icanhazip.com || curl -s ipinfo.io/ip)
echo -e "${OK} VPS Public IP: ${Green}$IP${NC}"

# Check root
if [[ $EUID -ne 0 ]]; then
    echo -e "${ERROR} Script must be run as root!"
    exit 1
fi

# Check Ubuntu
OS_ID=$(grep -w ID /etc/os-release | cut -d= -f2 | tr -d '"')
OS_VER=$(grep -w VERSION_ID /etc/os-release | cut -d= -f2 | tr -d '"')
if [[ "$OS_ID" != "ubuntu" ]]; then
    echo -e "${ERROR} Only Ubuntu is supported"
    exit 1
fi
echo -e "${OK} OS: Ubuntu $OS_VER"

# Update & install dependencies
echo -e "${OK} Installing dependencies..."
apt update -y
apt upgrade -y
apt install -y software-properties-common curl wget unzip zip sudo git lsof \
bash-completion figlet pwgen netcat socat chrony ntpdate iptables iptables-persistent \
netfilter-persistent ufw nano python3 python3-pip ruby gem build-essential dnsutils \
openssl cron htop tar p7zip-full ruby zip unzip ca-certificates gnupg \
debconf-utils jq bc

# Install lolcat for banner
gem install lolcat

# Set timezone
timedatectl set-timezone Asia/Jakarta

#=================================================
# Directories & Permissions
#=================================================
mkdir -p /etc/xray /etc/vmess /etc/vless /etc/trojan /etc/shadowsocks /etc/ssh /etc/bot \
/var/log/xray /usr/local/bin /var/lib/kyt /etc/kyt/limit/vmess/ip /etc/kyt/limit/vless/ip \
/etc/kyt/limit/trojan/ip /etc/kyt/limit/ssh/ip /var/www/html

chmod +x /var/log/xray
touch /var/log/xray/access.log
touch /var/log/xray/error.log
touch /etc/xray/domain

#=================================================
# HAProxy
#=================================================
echo -e "${OK} Installing HAProxy..."
apt install -y haproxy
systemctl enable haproxy
systemctl start haproxy

#=================================================
# Nginx
#=================================================
echo -e "${OK} Installing Nginx..."
apt install -y nginx
systemctl enable nginx
systemctl start nginx

#=================================================
# Install Xray Core
#=================================================
echo -e "${OK} Installing Xray Core..."
latest_version=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n1)
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data --version 1.8.23

# Download default configs
REPO="https://raw.githubusercontent.com/welwel11/project2/main/"
wget -O /etc/xray/config.json "${REPO}config/config.json"
wget -O /etc/systemd/system/runn.service "${REPO}files/runn.service"
chmod +x /etc/systemd/system/runn.service

#=================================================
# Domain & SSL
#=================================================
read -p "Enter your domain/subdomain: " DOMAIN
echo $DOMAIN > /etc/xray/domain
echo $DOMAIN > /root/domain

# Install acme.sh & issue certificate
mkdir -p /root/.acme.sh
curl https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
chmod +x /root/.acme.sh/acme.sh
/root/.acme.sh/acme.sh --upgrade --auto-upgrade
/root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
/root/.acme.sh/acme.sh --issue -d $DOMAIN --standalone -k ec-256
~/.acme.sh/acme.sh --installcert -d $DOMAIN --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc

cat /etc/xray/xray.crt /etc/xray/xray.key | tee /etc/haproxy/hap.pem

#=================================================
# SSH & Dropbear
#=================================================
echo -e "${OK} Installing Dropbear..."
apt install -y dropbear
wget -q -O /etc/default/dropbear "${REPO}config/dropbear.conf"
systemctl enable dropbear
systemctl restart dropbear

#=================================================
# SSHWS (SSH over WebSocket)
#=================================================
echo -e "${OK} Installing SSHWS (SSH over WebSocket)..."
wget -q -O /usr/local/bin/sshws "${REPO}files/sshws"
chmod +x /usr/local/bin/sshws

cat > /etc/systemd/system/sshws.service <<EOF
[Unit]
Description=SSH over WebSocket
After=network.target

[Service]
ExecStart=/usr/local/bin/sshws
Restart=on-failure
User=root
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable sshws
systemctl start sshws

#=================================================
# UDP Mini & SlowDNS
#=================================================
wget -q -O /usr/local/kyt/udp-mini "${REPO}files/udp-mini"
chmod +x /usr/local/kyt/udp-mini
for i in 1 2 3; do
    wget -q -O /etc/systemd/system/udp-mini-$i.service "${REPO}files/udp-mini-$i.service"
    systemctl enable udp-mini-$i
    systemctl start udp-mini-$i
done

wget -q -O /tmp/nameserver "${REPO}files/nameserver"
chmod +x /tmp/nameserver
bash /tmp/nameserver | tee /root/install.log

#=================================================
# vnStat
#=================================================
apt install -y vnstat libsqlite3-dev
wget https://humdi.net/vnstat/vnstat-2.6.tar.gz
tar zxvf vnstat-2.6.tar.gz
cd vnstat-2.6
./configure --prefix=/usr --sysconfdir=/etc && make && make install
cd
vnstat -u -i eth0
chown vnstat:vnstat /var/lib/vnstat -R
systemctl enable vnstat
systemctl restart vnstat

#=================================================
# Backup (rclone) & ePro
#=================================================
apt install -y rclone
mkdir -p /root/.config/rclone
wget -O /root/.config/rclone/rclone.conf "${REPO}config/rclone.conf"

wget -O /usr/bin/ws "${REPO}files/ws"
wget -O /etc/systemd/system/ws.service "${REPO}files/ws.service"
chmod +x /usr/bin/ws
systemctl enable ws
systemctl start ws

#=================================================
# Fail2ban
#=================================================
apt install -y fail2ban
wget -O /etc/kyt.txt "${REPO}files/issue.net"
echo "Banner /etc/kyt.txt" >> /etc/ssh/sshd_config
systemctl enable fail2ban
systemctl restart fail2ban

#=================================================
# rc.local
#=================================================
cat > /etc/rc.local <<EOF
#!/bin/sh -e
iptables -I INPUT -p udp --dport 5300 -j ACCEPT
iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300
systemctl restart netfilter-persistent
exit 0
EOF
chmod +x /etc/rc.local
systemctl enable rc-local
systemctl start rc-local

#=================================================
# Final enable services
#=================================================
systemctl daemon-reload
systemctl enable nginx haproxy xray dropbear sshws cron ws netfilter-persistent
systemctl restart nginx haproxy xray dropbear sshws cron ws netfilter-persistent

#=================================================
# Done
#=================================================
history -c
echo -e "${Green}All services installed successfully!${NC}"
echo "Rebooting VPS..."
reboot
