#!/bin/bash

# Cassandra Uninstall Script
# Usage: sudo bash uninstall-cassandra.sh

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root (use sudo)${NC}"
   exit 1
fi

echo -e "${YELLOW}This will completely remove Cassandra and all data!${NC}"
read -p "Are you sure? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Cancelled."
    exit 1
fi

echo -e "${GREEN}Stopping Cassandra service...${NC}"
systemctl stop cassandra 2>/dev/null
systemctl disable cassandra 2>/dev/null

echo -e "${GREEN}Removing service file...${NC}"
rm -f /etc/systemd/system/cassandra.service
systemctl daemon-reload

echo -e "${GREEN}Removing Cassandra installation...${NC}"
rm -rf /opt/cassandra

echo -e "${GREEN}Removing data directories...${NC}"
rm -rf /var/lib/cassandra
rm -rf /var/log/cassandra
rm -rf /var/run/cassandra

echo -e "${GREEN}Removing cassandra user...${NC}"
userdel -r cassandra 2>/dev/null

echo -e "${GREEN}Cassandra has been completely removed!${NC}"
