#!/bin/bash

VERSION=0.0.4
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

echo "Downloading binaries..."
rm /tmp/rri-proxy-bin
wget -O /tmp/rri-proxy-bin https://github.com/meklis/rri-proxy/releases/download/$VERSION/rri-proxy-linux-amd64
STATUS_BIN=$?
wget -O "$CONF_FILE" https://raw.githubusercontent.com/meklis/rri-proxy/$VERSION/proxy.conf.yml
STATUS_CONF=$?

if  [ $STATUS_BIN -eq 0 ] && [ $STATUS_CONF -eq 0 ]
then
  echo "Success download! Install..."
  echo "Check status of service"
  systemctl status rri-proxy && systemctl stop rri-proxy && rm /usr/local/bin/rri-proxy
  mv /tmp/rri-proxy-bin /usr/local/bin/rri-proxy
  chmod +x /usr/local/bin/rri-proxy
else
  echo "Failed download binaries"
  exit 2
fi

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
