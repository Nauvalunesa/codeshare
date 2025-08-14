#!/bin/bash

# Cassandra Status Check Script
# Usage: bash cassandra-status.sh

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=== Cassandra Status Check ===${NC}"

# Check if service is running
if systemctl is-active --quiet cassandra; then
    echo -e "${GREEN}✓ Service Status: Running${NC}"
else
    echo -e "${RED}✗ Service Status: Not Running${NC}"
    echo "Start with: sudo systemctl start cassandra"
    exit 1
fi

# Check CQL connection
echo -n "Testing CQL connection... "
if timeout 10 /opt/cassandra/bin/cqlsh -e "SELECT now() FROM system.local;" &>/dev/null; then
    echo -e "${GREEN}✓ Connected${NC}"
else
    echo -e "${RED}✗ Connection Failed${NC}"
    exit 1
fi

# Show cluster info
echo -e "\n${BLUE}Cluster Information:${NC}"
/opt/cassandra/bin/nodetool status

# Show keyspaces
echo -e "\n${BLUE}Available Keyspaces:${NC}"
/opt/cassandra/bin/cqlsh -e "DESCRIBE keyspaces;"

# Show disk usage
echo -e "\n${BLUE}Disk Usage:${NC}"
du -sh /var/lib/cassandra/data/* 2>/dev/null | head -10

# Show recent logs
echo -e "\n${BLUE}Recent Logs (last 10 lines):${NC}"
journalctl -u cassandra --no-pager -n 10

echo -e "\n${GREEN}Cassandra is healthy and ready!${NC}"
