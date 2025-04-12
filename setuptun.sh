#!/bin/bash

# Display usage information
show_usage() {
    echo "Usage: $0 <ip_address> <netmask>"
    echo "Example: $0 192.168.0.5 32"
    echo "Both IP address and netmask are required"
    exit 1
}

# Display usage if help is requested
if [[ "$1" == "--help" || "$1" == "-h" ]]; then
    show_usage
fi

# Check if both parameters are provided
if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Error: Both IP address and netmask are required"
    show_usage
fi

IP_ADDRESS="$1"
NETMASK="$2"

echo "Setting up TUN interface with IP: $IP_ADDRESS/$NETMASK"
ip tuntap add dev tun0 mode tun
ip addr add $IP_ADDRESS/$NETMASK dev tun0
ip link set dev tun0 up
ip addr show tun0
