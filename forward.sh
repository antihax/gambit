#!/bin/bash
kubectl get secret gambit-es-elastic-user -ngambit -o=jsonpath='{.data.elastic}' | base64 --decode; echo
kubectl port-forward service/gambit-es-http 9200:9200 -ngambit &
kubectl port-forward service/gambit-kb-http 5601:5601 -ngambit &
