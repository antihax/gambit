#!/bin/bash

kubectl get nodes -oname | grep worker | xargs -I{} kubectl label {} gambit=worker
kubectl get nodes -oname | grep conman | xargs -I{} kubectl label {} gambit=conman
