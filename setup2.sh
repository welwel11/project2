#!/usr/bin/env bash
set -e
export DEBIAN_FRONTEND=noninteractive

# ===== WARNA =====
GREEN="\e[32m"; RED="\e[31m"; YELLOW="\e[33m"; NC="\e[0m"

# ===== CEK ROOT =====
if [[ $EUID -ne 0 ]]; then
  echo -e "${RED}Run as root${NC}"
  exit 1
fi

# ===== CEK OS =====
source /etc/os-release
if [[ "$ID" != "ubuntu" || "$VERSION_ID" != "20.04" ]]; then
  echo -e "${RED}Only Ubuntu 20.04 supported${NC}"
  exit 1
fi

IP=$(curl -s ifconfig.me)
REPO="https://raw.githubusercontent.com/welwel11/project2/main"

echo -e "${GREEN}IP VPS : $IP${NC}"
sleep 2

# ===== BASE INSTALL =====
apt update -y
apt upgrade -y
apt install -y \
 curl wget unzip tar zip \
 ca-certificates gnupg lsb-release \
 sudo cron bash-completion \
 net-tools lsof htop jq \
 iptables iptables-persistent netfilter-persistent \
 nginx haproxy \
 chrony \
 openssl socat \
 vnstat fail2ban \
 openvpn easy-rsa \
 git screen rsyslog

# ===== TIMEZONE =====
timedatectl set-timezone Asia/Jakarta
systemctl enable chrony
systemctl restart chrony

# ===== XRAY DIR =====
mkdir -p /etc/xray /var/log/xray /var/www/html
touch /etc/xray/domain
touch /var/log/xray/access.log
touch /var/log/xray/error.log
chown -R www-data:www-data /var/log/xray

# ===== DOMAIN =====
clear
echo "1) Domain sendiri"
echo "2) Domain otomatis"
read -p "Pilih: " dmn
if [[ $dmn == "1" ]]; then
  read -p "Masukkan domain: " domain
  echo "$domain" > /etc/xray/domain
else
  wget -q ${REPO}/files/cf.sh -O /root/cf.sh
  chmod +x /root/cf.sh
  /root/cf.sh
fi

domain=$(cat /etc/xray/domain)

# ===== SSL =====
systemctl stop nginx || true
curl -s https://get.acme.sh | sh
~/.acme.sh/acme.sh --set-default-ca --server letsencrypt
~/.acme.sh/acme.sh --issue -d $domain --standalone
~/.acme.sh/acme.sh --installcert -d $domain \
 --keypath /etc/xray/xray.key \
 --fullchainpath /etc/xray/xray.crt
chmod 600 /etc/xray/xray.*

# ===== XRAY CORE =====
bash <(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)
wget -q -O /etc/xray/config.json ${REPO}/config/config.json

cat >/etc/systemd/system/xray.service <<EOF
[Unit]
Description=Xray Service
After=network.target

[Service]
User=www-data
ExecStart=/usr/local/bin/xray run -config /etc/xray/config.json
Restart=always
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable xray
systemctl restart xray

# ===== NGINX & HAPROXY =====
wget -q -O /etc/nginx/conf.d/xray.conf ${REPO}/config/xray.conf
wget -q -O /etc/haproxy/haproxy.cfg ${REPO}/config/haproxy.cfg
sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/xray.conf
sed -i "s/xxx/${domain}/g" /etc/haproxy/haproxy.cfg
cat /etc/xray/xray.crt /etc/xray/xray.key > /etc/haproxy/hap.pem

systemctl restart nginx
systemctl restart haproxy

# ===== SSH & DROPBEAR =====
wget -q -O /etc/ssh/sshd_config ${REPO}/files/sshd
systemctl restart ssh

apt install -y dropbear
wget -q -O /etc/default/dropbear ${REPO}/config/dropbear.conf
systemctl restart dropbear

# ===== FAIL2BAN =====
apt install -y fail2ban
systemctl enable --now fail2ban

# ===== VNSTAT =====
apt install -y vnstat
systemctl enable vnstat
systemctl restart vnstat

# ===== UDP MINI =====
wget -q ${REPO}/files/udp-mini -O /usr/local/bin/udp-mini
chmod +x /usr/local/bin/udp-mini

# ===== SLOWDNS =====
wget -q ${REPO}/files/nameserver -O /root/nameserver
chmod +x /root/nameserver
/root/nameserver

# ===== MENU =====
wget -q ${REPO}/menu/menu.zip
unzip -q menu.zip
chmod +x menu/*
mv menu/* /usr/local/sbin
rm -rf menu menu.zip

# ===== AUTOREBOOT =====
cat >/etc/cron.d/reboot <<EOF
0 3 * * * root /sbin/reboot
0 15 * * * root /sbin/reboot
EOF

# ===== CLEAN =====
apt autoremove -y
apt autoclean -y
history -c

echo -e "${GREEN}INSTALLATION FINISHED${NC}"
read -p "Press ENTER to reboot"
reboot