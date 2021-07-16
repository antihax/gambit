#!/bin/bash

# move SSH port to stop search bots hitting it and poluting logs
sed -i 's/^#*Port 22/Port 44/' /etc/ssh/sshd_config
service sshd restart

# turn swap off
swapoff -a
sed -i '/ swap / s/^\(.*\)$/#\1/g' /etc/fstab

modprobe overlay
modprobe br_netfilter

tee /etc/sysctl.d/kubernetes.conf<<EOF
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
net.ipv4.ip_forward = 1
EOF

sysctl --system

# bugfix: won't create CNI on occasion if this dir is not present
mkdir -p /etc/cni/net.d

# add kubernetes repo to apt
curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key add -
cat <<EOF > /etc/apt/sources.list.d/kubernetes.list  
deb http://apt.kubernetes.io/ kubernetes-xenial main  
EOF

# use official docker
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add -
add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"

# update apt repos and install docker, pwgen, and kubernetes
apt update -y
apt install -y containerd.io docker-ce docker-ce-cli curl gnupg2 software-properties-common apt-transport-https ca-certificates apt-transport-https pwgen kubelet kubeadm kubectl kubernetes-cni
apt upgrade -y
apt autoremove -y

mkdir -p /etc/systemd/system/docker.service.d

tee /etc/docker/daemon.json <<EOF
{
  "exec-opts": ["native.cgroupdriver=systemd"],
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "100m"
  },
  "storage-driver": "overlay2"
}
EOF

# Start and enable Services
systemctl daemon-reload 
systemctl restart docker
systemctl enable docker
