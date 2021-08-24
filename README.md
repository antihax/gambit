# GaMBiT
Collection of services to run a honeypot and analytics UI. Conman can also be ran as an internal sensor reporting to syslog to detect unwanted probes. This is a work in progress and just a fun project.

<a href="https://www.buymeacoffee.com/antihax" title="Donate to this project using Buy Me A Coffee"><img src="https://img.shields.io/badge/buy%20me%20a%20coffee-donate-yellow.svg" alt="Buy Me A Coffee donate button" /></a>

## Conman
The connection manager (Conman) attempts to sense the protocol based on matching the first few bytes of the packet, unwrapping TLS if detected, and forwarding on to a driver to attempt to extract more information about the session. A single port can seamlessly handle multiple protocols in this manner.

The current goal is to fake an endpoint long enough to collect passwords from the malefactor.

Conman can run as a docker container using host networking to consume all ports on a device and feed output to syslog.

### Services
| Service        | Description | 
| ------------- |-------------| 
| Conman      | Honeypot | 
| Contrive    | Frontend UI | 

### Infrastructure
Beats is utilized to consume syslog events from Conman, these are fed into elasticsearch.

Contrive performs queries against elasticsearch to provide a simple UI to consume the data.

Kibana can optionally be used, but is not currently exposed.

HAProxy provides Ingress to Contrive and leverages CertManager to obtain LetsEncrypt certificates through ACME.