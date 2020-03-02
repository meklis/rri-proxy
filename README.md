# Round robin interface proxy (RRI-Proxy)

## Requirements
- Ubuntu ^18.04
- systemd(systemctl)   

## Installation
- Download and run installation script 
```
wget https://raw.githubusercontent.com/meklis/rri-proxy/master/deamon/install.sh
chmod +x ./install.sh
./install.sh
```
- Make changes in configuration file     
File: */etc/rri-proxy/proxy.conf.yml*   
Details of parameters you find in comments in config file

## Command for control service
* Start - `systemctl start rri-proxy`
* Status - `systemctl status rri-proxy`
* Restart - `systemctl restart rri-proxy`
* Stop - `systemctl stop rri-proxy`
