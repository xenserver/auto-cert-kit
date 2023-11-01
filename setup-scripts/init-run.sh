#!/bin/bash
# This script is used to setup Driod VM template base on Rocky 8 Linux 8.6

# install dependencies for test tools
dnf update -y
dnf install perl -y
dnf --enablerepo=powertools install perl-List-MoreUtils -y
dnf --enablerepo=powertools install perl-Readonly -y
dnf install tcpdump -y

# setup firewall port for 4/tcp/udp and 5001/tcp/udp
firewall-cmd --zone=public --add-port=4/tcp --permanent
firewall-cmd --zone=public --add-port=4/udp --permanent
firewall-cmd --zone=public --add-port=5001/tcp --permanent
firewall-cmd --zone=public --add-port=5001/udp --permanent
firewall-cmd --reload
firewall-cmd --state

# setup static-ip service
cp /root/setup-scripts/static-ip.sh /root
chmod 755 /root/static-ip.sh
semanage fcontext -a -t bin_t '/root/static-ip.sh'
restorecon -Fv /root/static-ip.sh
cp /root/setup-scripts/startup-ip.service /lib/systemd/system/
systemctl enable startup-ip.service
systemctl start startup-ip.service
systemctl status startup-ip.service
