#!/bin/bash

#查看系统及内核版本
cat /etc/redhat-release
release=`cat /etc/redhat-release|sed -r 's/.* ([0-9]+)\..*/\1/'`
system=`cat /etc/redhat-release|awk '{print $1}'`
if [ "$release" == 7 ] && [ "$system" == CentOS ];then
	echo "系统为centos7可以安装！！！"
	sleep 5s
else
	echo "\033[31m \033[5m 系统版本错误，请使用centos7以上系统！！！\033[0m"
	exit
fi
	
#设置host
echo "192.168.30.148 node1" >>/etc/hosts
echo "192.168.30.147 master" >>/etc/hosts

#设置时间同步
yum -y install ntp
systemctl enable ntpd
systemctl start ntpd
ntpdate -u cn.pool.ntp.org
hwclock --systohc
timedatectl set-timezone Asia/Shanghai

#关闭swap分区
swapoff -a 
cp /etc/fstab /etc/fstab.bak
sed -i '/swap/d' /etc/fstab

#设置yum源
curl -o /etc/yum.repos.d/CentOS-Base.repo http://mirrors.aliyun.com/repo/Centos-7.repo
wget -O /etc/yum.repos.d/epel.repo http://mirrors.aliyun.com/repo/epel-7.repo
yum makecache
yum install wget vim lsof net-tools lrzsz -y

#关闭防火墙
systemctl stop firewalld
systemctl disable firewalld
setenforce 0
sed -i '/SELINUX/s/enforcing/disabled/' /etc/selinux/config

#升级内核
yum update -y
rpm --import https://www.elrepo.org/RPM-GPG-KEY-elrepo.org
rpm -Uvh http://www.elrepo.org/elrepo-release-7.0-2.el7.elrepo.noarch.rpm
yum --enablerepo=elrepo-kernel install kernel-ml -y&&
sed -i s/saved/0/g /etc/default/grub&&
grub2-mkconfig -o /boot/grub2/grub.cfg 

#设置内核参数
echo "* soft nofile 190000" >> /etc/security/limits.conf
echo "* hard nofile 200000" >> /etc/security/limits.conf
echo "* soft nproc 252144" >> /etc/security/limits.conf
echo "* hadr nproc 262144" >> /etc/security/limits.conf
tee /etc/sysctl.conf <<-'EOF'
# System default settings live in /usr/lib/sysctl.d/00-system.conf.
# To override those settings, enter new settings here, or in an /etc/sysctl.d/<name>.conf file
#
# For more information, see sysctl.conf(5) and sysctl.d(5).

net.ipv4.tcp_tw_recycle = 0
net.ipv4.ip_local_port_range = 10000 61000
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.ip_forward = 1
net.core.netdev_max_backlog = 2000
net.ipv4.tcp_mem = 131072  262144  524288
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 3
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_low_latency = 0
net.core.rmem_default = 256960
net.core.rmem_max = 513920
net.core.wmem_default = 256960
net.core.wmem_max = 513920
net.core.somaxconn = 2048
net.core.optmem_max = 81920
net.ipv4.tcp_mem = 131072  262144  524288
net.ipv4.tcp_rmem = 8760  256960  4088000
net.ipv4.tcp_wmem = 8760  256960  4088000
net.ipv4.tcp_keepalive_time = 1800
net.ipv4.tcp_sack = 1
net.ipv4.tcp_fack = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_syn_retries = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-arptables = 1
EOF
echo "options nf_conntrack hashsize=819200" >> /etc/modprobe.d/mlx4.conf 
modprobe br_netfilter
sysctl -p

#安装docker17.03
export docker_version=17.03.2
yum install -y yum-utils device-mapper-persistent-data lvm2 bash-completion
yum-config-manager --add-repo http://mirrors.aliyun.com/docker-ce/linux/centos/docker-ce.repo
yum makecache all
version=$(yum list docker-ce.x86_64 --showduplicates | sort -r|grep ${docker_version}|awk '{print $2}')
yum -y install --setopt=obsoletes=0 docker-ce-${version} docker-ce-selinux-${version}

reboot

