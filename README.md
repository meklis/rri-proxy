# Round robin interface proxy (RRI-Proxy)

## Requirements
- Ubuntu ^18.04
- systemd(systemctl)   

becouse app tested on :-)
```
# uname -a
Linux proxy 4.15.0-76-generic #86-Ubuntu SMP Fri Jan 17 17:24:28 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux

# lsb_release -a
Distributor ID: Ubuntu
Description:    Ubuntu 18.04.3 LTS
Release:        18.04
Codename:       bionic
```


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
