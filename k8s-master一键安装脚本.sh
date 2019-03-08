#!/bin/bash
set -e
#该脚本适应centos7系统环境
#脚本内需要修改master IP
#脚本初始位置在/k8s文件夹内，k8s程序包也需放在该文件内

#安装CFSSL
#client certificate     用于服务端认证客户端,例如etcdctl、etcd     proxy、fleetctl、docker客户端
#server certificate     服务端使用，客户端以此验证服务端身份,例如doc    ker服务端、kube-apiserver
#peer certificate     双向证书，用于etcd集群成员间通信
#安装CFSSL工具
wget https://pkg.cfssl.org/R1.2/cfssl_linux-amd64
chmod +x cfssl_linux-amd64
mv cfssl_linux-amd64 /usr/bin/cfssl
wget https://pkg.cfssl.org/R1.2/cfssljson_linux-amd64
chmod +x cfssljson_linux-amd64
mv cfssljson_linux-amd64 /usr/bin/cfssljson
wget https://pkg.cfssl.org/R1.2/cfssl-certinfo_linux-amd64
chmod +x cfssl-certinfo_linux-amd64
mv cfssl-certinfo_linux-amd64 /usr/bin/cfssl-certinfo
#生成ETCD证书
#etcd作为Kubernetes集群的主数据库，在安装Kubernetes各服务之前需要首先安装和启动
#创建CA证书
#创建etcd目录，用户生成etcd证书
mkdir /root/etcd_ssl 

cat > etcd-root-ca-csr.json << EOF
{
  "key": {
    "algo": "rsa",
    "size": 4096
  },
  "names": [
    {
      "O": "etcd",
      "OU": "etcd Security",
      "L": "beijing",
      "ST": "beijing",
      "C": "CN"
    }
  ],
  "CN": "etcd-root-ca"
}
EOF

#etcd集群证书

cat >  etcd-gencert.json << EOF  
{                                 
  "signing": {                    
    "default": {                  
      "expiry": "87600h"           
    },                            
    "profiles": {                 
      "etcd": {             
        "usages": [               
            "signing",            
            "key encipherment",   
            "server auth", 
            "client auth"  
        ],  
        "expiry": "87600h"  
      }  
    }  
  }  
}  
EOF
#过期时间设置成了 87600h
#ca-config.json：可以定义多个     profiles，分别指定不同的过期时间、使用场景等    参数；后续在签名证书时使用某个 profile；
#signing：表示该证书可用于签名其它证书；生成    的 ca.pem 证书中 CA=TRUE；
#server auth：表示client可以用该 CA     对server提供的证书进行验证；
#client auth：表示server可以用该CA对client提    供的证书进行验证；


#etcd证书签名请求
cat > etcd-csr.json << EOF
{
  "key": {
    "algo": "rsa",
    "size": 4096
  },
  "names": [
    {
      "O": "etcd",
      "OU": "etcd Security",
      "L": "beijing",
      "ST": "beijing",
      "C": "CN"
    }
  ],
  "CN": "etcd",
  "hosts": [
    "127.0.0.1",
    "localhost",
    "192.168.30.149"
  ]
}
EOF

# $hosts写master地址

#生成证书
cfssl gencert --initca=true     etcd-root-ca-csr.json | cfssljson --bare etcd-root-ca

#创建根CA

cfssl gencert --ca etcd-root-ca.pem \
--ca-key etcd-root-ca-key.pem \
--config etcd-gencert.json \
-profile=etcd etcd-csr.json | cfssljson     --bare etcd

echo "

开始检查证书数量.......

"
mv etc* /root/etcd_ssl/

cd /root/etcd_ssl/
car=`ls |wc -l`
if [ "$car" == 9 ];then
	echo -e "\033[32m 证书数量正常，安装继续！！！\033[0m"
	sleep 3s
else
	echo -e "\033[31m \033[5m 证书数量不正常，请检查证书生成过程！！！\033[0m"
	exit
fi


#安装启动ETCD
#ETCD 只有apiserver和Controller Manager需要连接
#分发etcd证书
yum install -y etcd
mkdir -p /etc/etcd/ssl 
#复制证书到相关目录
cp /root/etcd_ssl/*.pem /etc/etcd/ssl/
#groupadd etcd
#useradd etcd -g etcd
chown -R etcd:etcd /etc/etcd/ssl
chown -R etcd:etcd /var/lib/etcd
chmod -R 644 /etc/etcd/ssl/
chmod 755 /etc/etcd/ssl/

#配置修改ETCD-master配置

cp /etc/etcd/etcd.conf{,.bak} && >/etc/etcd/etcd.conf

###需要将192.168.30.149修改成master的地址
cat >/etc/etcd/etcd.conf <<EOF
# [member]
ETCD_NAME=etcd
ETCD_DATA_DIR="/var/lib/etcd/etcd.etcd"
ETCD_WAL_DIR="/var/lib/etcd/wal"
ETCD_SNAPSHOT_COUNT="100"
ETCD_HEARTBEAT_INTERVAL="100"
ETCD_ELECTION_TIMEOUT="1000"
ETCD_LISTEN_PEER_URLS="https://192.168.30.149:2380"
ETCD_LISTEN_CLIENT_URLS="https://192.168.30.149:2379,http://127.0.0.1:2379"
ETCD_MAX_SNAPSHOTS="5"
ETCD_MAX_WALS="5"
#ETCD_CORS=""

# [cluster]
ETCD_INITIAL_ADVERTISE_PEER_URLS="https://192.168.30.149:2380"
# if you use different ETCD_NAME (e.g. test), set ETCD_INITIAL_CLUSTER value for this name, i.e. "test=http://..."
ETCD_INITIAL_CLUSTER="etcd=https://192.168.30.149:2380"
ETCD_INITIAL_CLUSTER_STATE="new"
ETCD_INITIAL_CLUSTER_TOKEN="etcd-cluster"
ETCD_ADVERTISE_CLIENT_URLS="https://192.168.30.149:2379"
#ETCD_DISCOVERY=""
#ETCD_DISCOVERY_SRV=""
#ETCD_DISCOVERY_FALLBACK="proxy"
#ETCD_DISCOVERY_PROXY=""
#ETCD_STRICT_RECONFIG_CHECK="false"
#ETCD_AUTO_COMPACTION_RETENTION="0"

# [proxy]
#ETCD_PROXY="off"
#ETCD_PROXY_FAILURE_WAIT="5000"
#ETCD_PROXY_REFRESH_INTERVAL="30000"
#ETCD_PROXY_DIAL_TIMEOUT="1000"
#ETCD_PROXY_WRITE_TIMEOUT="5000"
#ETCD_PROXY_READ_TIMEOUT="0"

# [security]
ETCD_CERT_FILE="/etc/etcd/ssl/etcd.pem"
ETCD_KEY_FILE="/etc/etcd/ssl/etcd-key.pem"
ETCD_CLIENT_CERT_AUTH="true"
ETCD_TRUSTED_CA_FILE="/etc/etcd/ssl/etcd-root-ca.pem"
ETCD_AUTO_TLS="true"
ETCD_PEER_CERT_FILE="/etc/etcd/ssl/etcd.pem"
ETCD_PEER_KEY_FILE="/etc/etcd/ssl/etcd-key.pem"
ETCD_PEER_CLIENT_CERT_AUTH="true"
ETCD_PEER_TRUSTED_CA_FILE="/etc/etcd/ssl/etcd-root-ca.pem"
ETCD_PEER_AUTO_TLS="true"

# [logging]
#ETCD_DEBUG="false"
# examples for -log-package-levels etcdserver=WARNING,security=DEBUG
#ETCD_LOG_PACKAGE_LEVELS=""
EOF


#启动etcd

systemctl daemon-reload
systemctl restart etcd
systemctl enable etcd

#查看2379 ETCD端口

netstat -lntup

sleep 3s


#修改docker配置

#设置开机启动并启动docker
systemctl enable docker 
systemctl start docker 

#替换docker相关配置
sed -i '/ExecStart=\/usr\/bin\/dockerd/i\ExecStartPost=\/sbin/iptables -I FORWARD -s 0.0.0.0\/0 -d 0.0.0.0\/0 -j ACCEPT' /usr/lib/systemd/system/docker.service
sed -i '/dockerd/s/$/ \-\-storage\-driver\=overlay2/g' /usr/lib/systemd/system/docker.service

#重启docker
systemctl daemon-reload 
systemctl restart docker

#执行停止，等待用户确认
while true;do
stty -icanon min 0 time 100
echo -n "确认kubernetes-server-linux-amd64.tar.gz安装包是否提前下载到文件夹下(yes or no)?"
read Arg
case $Arg in
Y|y|YES|yes)
  break;;
N|n|NO|no)
   echo "请到 https://github.com/kubernetes/kubernetes/releases 该地址下载kubernetes-server-linux-amd64.tar.gz文件......"
  ;;
"")  #Autocontinue
  break;;
esac
done

#安装Kubernetes
cd /k8s
tar xf kubernetes-server-linux-amd64.tar.gz
for i in hyperkube kube-apiserver kube-scheduler kubelet kube-controller-manager kubectl kube-proxy;do
cp ./kubernetes/server/bin/$i /usr/bin/
chmod 755 /usr/bin/$i
done


#生成分发Kubernetes证书
#设置证书目录
mkdir /root/kubernets_ssl
cd /root/kubernets_ssl
#k8s-root-ca-csr.json证书
cat > k8s-root-ca-csr.json << EOF
{
  "CN": "kubernetes",
  "key": {
    "algo": "rsa",
    "size": 4096
  },
  "names": [
    {
      "C": "CN",
      "ST": "BeiJing",
      "L": "BeiJing",
      "O": "k8s",
      "OU": "System"
    }
  ]
}
EOF

#k8s-gencert.json证书
cat >  k8s-gencert.json << EOF
{
  "signing": {
    "default": {
      "expiry": "87600h"
    },
    "profiles": {
      "kubernetes": {
        "usages": [
            "signing",
            "key encipherment",
            "server auth",
            "client auth"
        ],
        "expiry": "87600h"
      }
    }
  }
}
EOF


#kubernetes-csr.json 证书

#$ hosts字段填写上所有你要用到的节点ip(master)，创建 kubernetes 证书签名请求文件 kubernetes-csr.json

cat >kubernetes-csr.json << EOF
{
    "CN": "kubernetes",
    "hosts": [
        "127.0.0.1",
        "10.254.0.1",
        "192.168.30.149",
        "localhost",
        "kubernetes",
        "kubernetes.default",
        "kubernetes.default.svc",
        "kubernetes.default.svc.cluster",
        "kubernetes.default.svc.cluster.local"
    ],
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "C": "CN",
            "ST": "BeiJing",
            "L": "BeiJing",
            "O": "k8s",
            "OU": "System"
        }
    ]
}
EOF


#kube-proxy-csr.json 证书

cat > kube-proxy-csr.json << EOF
{
  "CN": "system:kube-proxy",
  "hosts": [],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "ST": "BeiJing",
      "L": "BeiJing",
      "O": "k8s",
      "OU": "System"
    }
  ]
}
EOF

#admin-csr.json证书

cat > admin-csr.json << EOF
{
  "CN": "admin",
  "hosts": [],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "ST": "BeiJing",
      "L": "BeiJing",
      "O": "system:masters",
      "OU": "System"
    }
  ]
}
EOF

#生成Kubernetes证书
cfssl gencert --initca=true k8s-root-ca-csr.json | cfssljson --bare k8s-root-ca
for targetName in kubernetes admin kube-proxy; do
    cfssl gencert --ca k8s-root-ca.pem --ca-key k8s-root-ca-key.pem --config k8s-gencert.json --profile kubernetes $targetName-csr.json | cfssljson --bare $targetName
done


#生成boostrap配置

export KUBE_APISERVER="https://192.168.30.149:6443"
export BOOTSTRAP_TOKEN=$(head -c 16 /dev/urandom | od -An -t x | tr -d ' ')
BOOTSTRAP_TOKEN=`head -c 16 /dev/urandom | od -An -t x | tr -d ' '`
KUBE_APISERVER="https://192.168.30.149:6443"
echo "Tokne: ${BOOTSTRAP_TOKEN}"
cat > token.csv <<EOF
${BOOTSTRAP_TOKEN},kubelet-bootstrap,10001,"system:kubelet-bootstrap"
EOF

#配置证书信息

kubectl config set-cluster kubernetes \
  --certificate-authority=k8s-root-ca.pem \
  --embed-certs=true \
  --server=${KUBE_APISERVER} \
  --kubeconfig=bootstrap.kubeconfig

# 设置客户端认证参数

kubectl config set-credentials kubelet-bootstrap \
  --token=${BOOTSTRAP_TOKEN} \
  --kubeconfig=bootstrap.kubeconfig
# 设置上下文参数

kubectl config set-context default \
  --cluster=kubernetes \
  --user=kubelet-bootstrap \
  --kubeconfig=bootstrap.kubeconfig
# 设置默认上下文

kubectl config use-context default --kubeconfig=bootstrap.kubeconfig
# echo "Create kube-proxy kubeconfig..."

kubectl config set-cluster kubernetes \
  --certificate-authority=k8s-root-ca.pem \
  --embed-certs=true \
  --server=${KUBE_APISERVER} \
  --kubeconfig=kube-proxy.kubeconfig
# kube-proxy

kubectl config set-credentials kube-proxy \
  --client-certificate=kube-proxy.pem \
  --client-key=kube-proxy-key.pem \
  --embed-certs=true \
  --kubeconfig=kube-proxy.kubeconfig
# kube-proxy_config

kubectl config set-context default \
  --cluster=kubernetes \
  --user=kube-proxy \
  --kubeconfig=kube-proxy.kubeconfig 
kubectl config use-context default --kubeconfig=kube-proxy.kubeconfig
# 生成高级审计配置

cat >> audit-policy.yaml <<EOF
# Log all requests at the Metadata level.
apiVersion: audit.k8s.io/v1beta1
kind: Policy
rules:
- level: Metadata
EOF
#分发kubernetes证书#####
cd /root/kubernets_ssl
mkdir -p /etc/kubernetes/ssl
cp *.pem /etc/kubernetes/ssl
\cp *.kubeconfig token.csv audit-policy.yaml /etc/kubernetes
#useradd -s /sbin/nologin -M kube
chown -R kube:kube /etc/kubernetes/ssl
# 生成kubectl的配置

cd /root/kubernets_ssl
kubectl config set-cluster kubernetes \
  --certificate-authority=/etc/kubernetes/ssl/k8s-root-ca.pem \
  --embed-certs=true \
  --server=https://192.168.30.149:6443

  
  
kubectl config set-credentials admin \
  --client-certificate=/etc/kubernetes/ssl/admin.pem \
  --embed-certs=true \
  --client-key=/etc/kubernetes/ssl/admin-key.pem

  
kubectl config set-context kubernetes \
  --cluster=kubernetes \
  --user=admin

  
kubectl config use-context kubernetes
# 设置 log 目录权限

mkdir -p /var/log/kube-audit /usr/libexec/kubernetes
chown -R kube:kube /var/log/kube-audit /usr/libexec/kubernetes
chmod -R 755 /var/log/kube-audit /usr/libexec/kubernetes

#Master操作

cd /etc/kubernetes
#config 通用配置

#以下操作不提示默认即可，需要修改已注释

cat > /etc/kubernetes/config <<EOF
###
# kubernetes system config
#
# The following values are used to configure various aspects of all
# kubernetes services, including
#
#   kube-apiserver.service
#   kube-controller-manager.service
#   kube-scheduler.service
#   kubelet.service
#   kube-proxy.service
# logging to stderr means we get it in the systemd journal
KUBE_LOGTOSTDERR="--logtostderr=true"

# journal message level, 0 is debug
KUBE_LOG_LEVEL="--v=2"

# Should this cluster be allowed to run privileged docker containers
KUBE_ALLOW_PRIV="--allow-privileged=true"

# How the controller-manager, scheduler, and proxy find the apiserver
KUBE_MASTER="--master=http://127.0.0.1:8080"
EOF

#apiserver 配置

cat > /etc/kubernetes/apiserver <<EOF
###
# kubernetes system config
#
# The following values are used to configure the kube-apiserver
#

# The address on the local server to listen to.
KUBE_API_ADDRESS="--advertise-address=0.0.0.0 --insecure-bind-address=0.0.0.0 --bind-address=0.0.0.0"

# The port on the local server to listen on.
KUBE_API_PORT="--insecure-port=8080 --secure-port=6443"

# Port minions listen on
# KUBELET_PORT="--kubelet-port=10250"

# Comma separated list of nodes in the etcd cluster
KUBE_ETCD_SERVERS=--etcd-servers=https://192.168.30.149:2379 ##etcd地址

# Address range to use for services
KUBE_SERVICE_ADDRESSES="--service-cluster-ip-range=10.254.0.0/16"

# default admission control policies
KUBE_ADMISSION_CONTROL="--admission-control=NamespaceLifecycle,LimitRanger,ServiceAccount,ResourceQuota,NodeRestriction"

# Add your own!
KUBE_API_ARGS="--authorization-mode=RBAC,Node \
               --endpoint-reconciler-type=lease \
               --runtime-config=batch/v2alpha1=true \
               --anonymous-auth=false \
               --kubelet-https=true \
               --enable-bootstrap-token-auth \
               --token-auth-file=/etc/kubernetes/token.csv \
               --service-node-port-range=30000-50000 \
               --tls-cert-file=/etc/kubernetes/ssl/kubernetes.pem \
               --tls-private-key-file=/etc/kubernetes/ssl/kubernetes-key.pem \
               --client-ca-file=/etc/kubernetes/ssl/k8s-root-ca.pem \
               --service-account-key-file=/etc/kubernetes/ssl/k8s-root-ca-key.pem \
               --etcd-quorum-read=true \
               --storage-backend=etcd3 \
               --etcd-cafile=/etc/etcd/ssl/etcd-root-ca.pem \
               --etcd-certfile=/etc/etcd/ssl/etcd.pem \
               --etcd-keyfile=/etc/etcd/ssl/etcd-key.pem \
               --enable-swagger-ui=true \
               --apiserver-count=3 \
               --audit-policy-file=/etc/kubernetes/audit-policy.yaml \
               --audit-log-maxage=30 \
               --audit-log-maxbackup=3 \
               --audit-log-maxsize=100 \
               --audit-log-path=/var/log/kube-audit/audit.log \
               --event-ttl=1h "
EOF

#需要修改的地址是etcd的，集群逗号为分隔符填写
#controller-manager 配置

cat > /etc/kubernetes/controller-manager <<EOF
###
# The following values are used to configure the kubernetes controller-manager

# defaults from config and apiserver should be adequate

# Add your own!
KUBE_CONTROLLER_MANAGER_ARGS="--address=0.0.0.0 \
                              --service-cluster-ip-range=10.254.0.0/16 \
                              --cluster-name=kubernetes \
                              --cluster-signing-cert-file=/etc/kubernetes/ssl/k8s-root-ca.pem \
                              --cluster-signing-key-file=/etc/kubernetes/ssl/k8s-root-ca-key.pem \
                              --service-account-private-key-file=/etc/kubernetes/ssl/k8s-root-ca-key.pem \
                              --root-ca-file=/etc/kubernetes/ssl/k8s-root-ca.pem \
                              --leader-elect=true \
                              --node-monitor-grace-period=40s \
                              --node-monitor-period=5s \
                              --pod-eviction-timeout=60s"
EOF

#scheduler 配置

cat >scheduler <<EOF
###
# kubernetes scheduler config

# default config should be adequate

# Add your own!
KUBE_SCHEDULER_ARGS="--leader-elect=true --address=0.0.0.0"
EOF


#设置服务启动脚本
#Kubernetes服务的组件配置已经生成，接下来我们配置组件的启动脚本
###kube-apiserver.service服务脚本###

cat >/usr/lib/systemd/system/kube-apiserver.service <<EOF

[Unit]
Description=Kubernetes API Server
Documentation=https://github.com/GoogleCloudPlatform/kubernetes
After=network.target
After=etcd.service

[Service]
EnvironmentFile=-/etc/kubernetes/config
EnvironmentFile=-/etc/kubernetes/apiserver
User=root
ExecStart=/usr/bin/kube-apiserver \
        \$KUBE_LOGTOSTDERR \\
        \$KUBE_LOG_LEVEL \\
        \$KUBE_ETCD_SERVERS \\
        \$KUBE_API_ADDRESS \\
        \$KUBE_API_PORT \\
        \$KUBELET_PORT \\
        \$KUBE_ALLOW_PRIV \\
        \$KUBE_SERVICE_ADDRESSES \\
        \$KUBE_ADMISSION_CONTROL \\
        \$KUBE_API_ARGS
Restart=on-failure
Type=notify
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF


###kube-controller-manager.service服务脚本###


cat > /usr/lib/systemd/system/kube-controller-manager.service <<EOF
[Unit]
Description=Kubernetes Controller Manager
Documentation=https://github.com/GoogleCloudPlatform/kubernetes

[Service]
EnvironmentFile=-/etc/kubernetes/config
EnvironmentFile=-/etc/kubernetes/controller-manager
User=root
ExecStart=/usr/bin/kube-controller-manager \\
        \$KUBE_LOGTOSTDERR \\
        \$KUBE_LOG_LEVEL \\
        \$KUBE_MASTER \\
        \$KUBE_CONTROLLER_MANAGER_ARGS
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF


###kube-scheduler.service服务脚本###

cat > /usr/lib/systemd/system/kube-scheduler.service << EOF
[Unit]
Description=Kubernetes Scheduler Plugin
Documentation=https://github.com/GoogleCloudPlatform/kubernetes

[Service]
EnvironmentFile=-/etc/kubernetes/config
EnvironmentFile=-/etc/kubernetes/scheduler
User=root
ExecStart=/usr/bin/kube-scheduler \\
        \$KUBE_LOGTOSTDERR \\
        \$KUBE_LOG_LEVEL \\
        \$KUBE_MASTER \\
        \$KUBE_SCHEDULER_ARGS
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

#启动kube-apiserver、kube-controller-manager、kube-schedule

systemctl daemon-reload
systemctl start kube-apiserver
systemctl start kube-controller-manager
systemctl start kube-scheduler


#设置开机启动
systemctl enable kube-apiserver
systemctl enable kube-controller-manager
systemctl enable kube-scheduler

echo "

提示：kube-apiserver是主要服务，如果apiserver启动失败其他的也会失败
等待120s查看日志 /var/log/message
"
sleep 120s

kubectl get cs
echo "

若状态为此类则服务正常

NAME                 STATUS    MESSAGE              ERROR
controller-manager   Healthy   ok                   
scheduler            Healthy   ok                   
etcd-0               Healthy   {"health": "true"} 

"

#创建ClusterRoleBinding

kubectl create clusterrolebinding kubelet-bootstrap \
--clusterrole=system:node-bootstrapper \
--user=kubelet-bootstrap


#Master 上安装node节点
echo "

\033[32m 请选择是否在master节点上安装node节点 \033[0m

"

while true;do
stty -icanon min 0 time 100
echo -n "是否在master上安装node节点(yes or no)?"
read Arg
case $Arg in
Y|y|YES|yes)
cat > /etc/kubernetes/kubelet<<EOF
 ###
# kubernetes kubelet (minion) config

# The address for the info server to serve on (set to 0.0.0.0 or "" for all interfaces)
KUBELET_ADDRESS="--address=192.168.30.149"

# The port for the info server to serve on
# KUBELET_PORT="--port=10250"

# You may leave this blank to use the actual hostname
KUBELET_HOSTNAME="--hostname-override=master"

# location of the api-server
# KUBELET_API_SERVER=""

# Add your own!
KUBELET_ARGS="--cgroup-driver=cgroupfs \\
              --cluster-dns=10.254.0.2 \\
              --resolv-conf=/etc/resolv.conf \\
              --experimental-bootstrap-kubeconfig=/etc/kubernetes/bootstrap.kubeconfig \\
              --kubeconfig=/etc/kubernetes/kubelet.kubeconfig \\
              --cert-dir=/etc/kubernetes/ssl \\
              --cluster-domain=cluster.local. \\
              --hairpin-mode promiscuous-bridge \\
              --serialize-image-pulls=false \\
              --pod-infra-container-image=gcr.io/google_containers/pause-amd64:3.0" 
EOF
#将IP地址修改为master上的IP地址和主机名，其他不需要修改
#创建服务脚本
###kubelet.service服务脚本###
#文件名称：kubelet.service

cat > /usr/lib/systemd/system/kubelet.service <<EOF
[Unit]
Description=Kubernetes Kubelet Server
Documentation=https://github.com/GoogleCloudPlatform/kubernetes
After=docker.service
Requires=docker.service

[Service]
WorkingDirectory=/var/lib/kubelet
EnvironmentFile=-/etc/kubernetes/config
EnvironmentFile=-/etc/kubernetes/kubelet
ExecStart=/usr/bin/kubelet \\
        \$KUBE_LOGTOSTDERR \\
        \$KUBE_LOG_LEVEL \\
        \$KUBELET_API_SERVER \\
        \$KUBELET_ADDRESS \\
        \$KUBELET_PORT \\
        \$KUBELET_HOSTNAME \\
        \$KUBE_ALLOW_PRIV \\
        \$KUBELET_ARGS
Restart=on-failure
KillMode=process

[Install]
WantedBy=multi-user.target
EOF

#创建工程目录
mkdir /var/lib/kubelet -p

#kube-proxy配置
cat >/etc/kubernetes/proxy <<EOF
###
# kubernetes proxy config

# default config should be adequate

# Add your own!
KUBE_PROXY_ARGS="--bind-address=192.168.30.149 \\
                 --hostname-override=master \\
                 --kubeconfig=/etc/kubernetes/kube-proxy.kubeconfig \\
                 --cluster-cidr=10.254.0.0/16"
EOF

#master ip && name
#kube-proxy启动脚本
cat >/usr/lib/systemd/system/kube-proxy.service<<EOF
[Unit]
Description=Kubernetes Kube-Proxy Server
Documentation=https://github.com/GoogleCloudPlatform/kubernetes
After=network.target

[Service]
EnvironmentFile=-/etc/kubernetes/config
EnvironmentFile=-/etc/kubernetes/proxy
ExecStart=/usr/bin/kube-proxy \\
        \$KUBE_LOGTOSTDERR \\
        \$KUBE_LOG_LEVEL \\
        \$KUBE_MASTER \\
        \$KUBE_PROXY_ARGS
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
#启动kubelet and Kube-proxy
echo "

重启kubelet

"
systemctl daemon-reload
systemctl restart kube-proxy
systemctl restart kubelet
sleep 30s
echo "当出现数据表明kubelet安装正常...."
kubectl get csr
  break;;
N|n|NO|no)
  break;;
"")  #Autocontinue
  break;;
esac
done

echo  "k8s master安装完成"
