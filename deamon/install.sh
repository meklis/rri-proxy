#!/bin/bash

VERSION=0.0.3
CONF_FILE=/etc/rri-proxy/proxy.conf.yml

echo "Installing rri-proxy, ver. $VERSION"

if [ -e "$CONF_FILE" ]; then
  echo "Defined old configuration $CONF_FILE, file not be updated"
  echo "Example of new configuration file will be saved to /etc/rri-proxy/example.proxy.conf.yml"
  CONF_FILE=/etc/rri-proxy/example.proxy.conf.yml
else
  CONF_FILE=/etc/rri-proxy/proxy.conf.yml
fi

echo "Creating destination directory..."
mkdir -p /etc/rri-proxy
mkdir -p /usr/local/bin

CODE=0
echo "Downloading binaries..."
wget -O /usr/local/bin/rri-proxy https://github.com/meklis/rri-proxy/releases/download/$VERSION/rri-proxy-linux-amd64
[ $? -eq 0 ]  || CODE=1
wget -O "$CONF_FILE" https://raw.githubusercontent.com/meklis/rri-proxy/$VERSION/proxy.conf.yml
[ $? -eq 0 ]  || CODE=1
chmod +x /usr/local/bin/rri-proxy


echo "Status code of downloading $CODE"
echo ""
echo "Register service in systemd..."
echo "
[Unit]
Description=Proxy with round robin interfaces
After=network.target
StartLimitIntervalSec=0
[Service]
Type=simple
Restart=always
RestartSec=1
User=root
LimitNOFILE=128000
ExecStart=/usr/local/bin/rri-proxy -c /etc/rri-proxy/proxy.conf.yml
[Install]
WantedBy=multi-user.target
" > /etc/systemd/system/rri-proxy.service

systemctl enable rri-proxy

echo "Installation finished!"
echo ""
echo "Command for get service status:"
echo "    systemctl status rri-proxy"
echo ""
echo "Command for start service:"
echo "    systemctl start rri-proxy"
