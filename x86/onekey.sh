#!/bin/bash
apt-get update
mkdir ocserv
mkdir /etc/ocserv
cd ocserv
wget "https://raw.githubusercontent.com/HaloWww/ocserv/refs/heads/main/x86/ocserv.service"
wget "https://raw.githubusercontent.com/HaloWww/ocserv/refs/heads/main/x86/occtl"
wget "https://raw.githubusercontent.com/HaloWww/ocserv/refs/heads/main/x86/ocpasswd"
wget "https://raw.githubusercontent.com/HaloWww/ocserv/refs/heads/main/x86/ocserv"
wget "https://raw.githubusercontent.com/HaloWww/ocserv/refs/heads/main/x86/ocserv-fw"
wget "https://raw.githubusercontent.com/HaloWww/ocserv/refs/heads/main/x86/ocserv-worker"
wget "https://raw.githubusercontent.com/HaloWww/ocserv/refs/heads/main/x86/ocserv.conf"

cp ocserv /usr/sbin/ocserv
cp ocserv-worker  /usr/sbin/ocserv-worker
cp ocserv-fw /usr/bin/ocserv-fw
cp occtl /usr/bin/
cp ocpasswd /usr/bin/
cp ocserv.service /etc/systemd/system/ocserv.service
cp -f ocserv.conf /etc/ocserv/

systemctl daemon-reload
systemctl enable ocserv
systemctl start ocserv

echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
echo "net.core.default_qdisc = fq" >> /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf
sysctl -p

ufw allow 23556
ufw allow 22

sed -i 's/DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw

interface=$(ip route | grep default | awk '{print $5}')
sudo sed -i '1i# START VPN RULES\n# NAT table rules\n*nat\n:POSTROUTING ACCEPT [0:0]\n-A POSTROUTING -s 192.168.88.0/24 -o $interface -j MASQUERADE\nCOMMIT\n# END VPN RULES\n' /etc/ufw/before.rules

ufw enable
ufw reload
apt install certbot
certbot certonly

nano /root/ca-cert.pem
nano 
