#!/bin/bash

# start master node
kubeadm init

# copy kubectl config
mkdir -p $HOME/.kube
cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
chown $(id -u):$(id -g) $HOME/.kube/config
export kubeconfig=/etc/kubernetes/admin.conf

# create weavenet and set random encryption password
kubectl apply -f "https://cloud.weave.works/k8s/net?k8s-version=$(kubectl version | base64 | tr -d '\n')"
kubectl create secret -n kube-system generic weave-passwd --from-literal=weave-passwd=`pwgen 32 1 -sy`
kubectl patch daemonset -n kube-system --type=json weave-net -p '[{"op": "add", "path": "/spec/template/spec/containers/0/env/1", "value": {"name":"WEAVE_PASSWORD","valueFrom":{"secretKeyRef":{"name":"weave-passwd","key":"weave-passwd"}}}}]'
kubectl patch daemonset -n kube-system --type=json weave-net -p '[{"op": "add", "path": "/spec/template/spec/containers/0/env/1", "value": {"name":"EXTRA_ARGS","value":"--log-level=error"}}]'

# fix local host DNS issues, use google and cloudflare instead
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: kube-dns
  namespace: kube-system
  labels:
    addonmanager.kubernetes.io/mode: EnsureExists
data:
  upstreamNameservers: |-
    ["8.8.8.8", "1.1.1.1"]
EOF

# restart kubernetes pods to make sure everything is now clean
kubectl delete pod --all -n kube-system

# setup helm
curl https://raw.githubusercontent.com/helm/helm/master/scripts/get-helm-3 | bash
helm repo add haproxytech https://haproxytech.github.io/helm-charts
helm repo update

# setup haproxy ingress
kubectl create namespace haproxy
helm install haproxy haproxytech/kubernetes-ingress \
  --namespace=haproxy \
  --set controller.kind=DaemonSet \
  --set controller.daemonset.useHostPort=true \
  --set controller.nodeSelector.ingress=haproxy

# setup cert manager
kubectl apply -f https://github.com/jetstack/cert-manager/releases/latest/download/cert-manager.yaml

# add eck for elastic
kubectl create -f https://download.elastic.co/downloads/eck/2.1.0/crds.yaml
kubectl apply -f https://download.elastic.co/downloads/eck/2.1.0/operator.yaml


# hetzner volumes
#kubectl apply -f https://raw.githubusercontent.com/hetznercloud/csi-driver/v1.6.0/deploy/kubernetes/hcloud-csi.yml

# local volumes
helm repo add openebs https://openebs.github.io/charts
helm repo update
helm install openebs --namespace openebs openebs/openebs --create-namespace
kubectl apply -f https://openebs.github.io/charts/examples/local-hostpath/local-hostpath-pvc.yaml
kubectl apply -f https://openebs.github.io/charts/examples/local-hostpath/local-hostpath-pod.yaml

# create namespace
kubectl apply -f gambit.yaml