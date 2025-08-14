#!/bin/bash

# Cassandra VPS Setup Script
# Supports Ubuntu/Debian and CentOS/RHEL
# Run with: sudo bash setup-cassandra.sh

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}"
    exit 1
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root (use sudo)"
fi

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$NAME
    VER=$VERSION_ID
else
    error "Cannot detect OS version"
fi

log "Detected OS: $OS $VER"

# Update system
log "Updating system packages..."
if [[ "$OS" == *"Ubuntu"* ]] || [[ "$OS" == *"Debian"* ]]; then
    apt update && apt upgrade -y
    PACKAGE_MANAGER="apt"
elif [[ "$OS" == *"CentOS"* ]] || [[ "$OS" == *"Red Hat"* ]] || [[ "$OS" == *"Rocky"* ]]; then
    yum update -y || dnf update -y
    PACKAGE_MANAGER="yum"
else
    error "Unsupported OS: $OS"
fi

# Install Java 11
log "Installing Java 11..."
if [[ "$PACKAGE_MANAGER" == "apt" ]]; then
    apt install -y openjdk-11-jdk wget curl gnupg2
elif [[ "$PACKAGE_MANAGER" == "yum" ]]; then
    yum install -y java-11-openjdk java-11-openjdk-devel wget curl
fi

# Verify Java installation
java -version
if [ $? -ne 0 ]; then
    error "Java installation failed"
fi

# Set JAVA_HOME
JAVA_HOME=$(readlink -f /usr/bin/java | sed "s:bin/java::")
echo "export JAVA_HOME=$JAVA_HOME" >> /etc/environment
export JAVA_HOME=$JAVA_HOME
log "JAVA_HOME set to: $JAVA_HOME"

# Create cassandra user
log "Creating cassandra user..."
if ! id "cassandra" &>/dev/null; then
    useradd -r -m -U -d /var/lib/cassandra -s /bin/bash cassandra
    log "Cassandra user created"
else
    log "Cassandra user already exists"
fi

# Download and install Cassandra
CASSANDRA_VERSION="4.1.3"
log "Downloading Cassandra $CASSANDRA_VERSION..."

cd /tmp
wget "https://archive.apache.org/dist/cassandra/$CASSANDRA_VERSION/apache-cassandra-$CASSANDRA_VERSION-bin.tar.gz"

if [ ! -f "apache-cassandra-$CASSANDRA_VERSION-bin.tar.gz" ]; then
    error "Failed to download Cassandra"
fi

# Extract Cassandra
log "Installing Cassandra..."
tar -xzf "apache-cassandra-$CASSANDRA_VERSION-bin.tar.gz"
mv "apache-cassandra-$CASSANDRA_VERSION" /opt/cassandra
chown -R cassandra:cassandra /opt/cassandra

# Create directories
log "Creating Cassandra directories..."
mkdir -p /var/lib/cassandra/{data,commitlog,saved_caches,hints}
mkdir -p /var/log/cassandra
chown -R cassandra:cassandra /var/lib/cassandra
chown -R cassandra:cassandra /var/log/cassandra

# Configure Cassandra
log "Configuring Cassandra..."
CASSANDRA_CONF="/opt/cassandra/conf/cassandra.yaml"

# Backup original config
cp $CASSANDRA_CONF ${CASSANDRA_CONF}.backup

# Get server IP
SERVER_IP=$(curl -s ifconfig.me || hostname -I | awk '{print $1}')
log "Server IP detected: $SERVER_IP"

# Update configuration
cat > $CASSANDRA_CONF << EOF
# Cassandra Configuration
cluster_name: 'Lunox Cluster'
num_tokens: 256
hinted_handoff_enabled: true
max_hint_window_in_ms: 10800000
hinted_handoff_throttle_in_kb: 1024
max_hints_delivery_threads: 2
hints_directory: /var/lib/cassandra/hints
hints_flush_period_in_ms: 10000
max_hints_file_size_in_mb: 128
batchlog_replay_throttle_in_kb: 1024
authenticator: AllowAllAuthenticator
authorizer: AllowAllAuthorizer
role_manager: CassandraRoleManager
roles_validity_in_ms: 2000
permissions_validity_in_ms: 2000
credentials_validity_in_ms: 2000
partitioner: org.apache.cassandra.dht.Murmur3Partitioner
data_file_directories:
    - /var/lib/cassandra/data
commitlog_directory: /var/lib/cassandra/commitlog
disk_failure_policy: stop
commit_failure_policy: stop
prepared_statements_cache_size_mb:
thrift_prepared_statements_cache_size_mb:
key_cache_size_in_mb:
key_cache_save_period: 14400
row_cache_size_in_mb: 0
row_cache_save_period: 0
counter_cache_size_in_mb:
counter_cache_save_period: 7200
saved_caches_directory: /var/lib/cassandra/saved_caches
commitlog_sync: periodic
commitlog_sync_period_in_ms: 10000
commitlog_segment_size_in_mb: 32
seed_provider:
    - class_name: org.apache.cassandra.locator.SimpleSeedProvider
      parameters:
          - seeds: "127.0.0.1"
concurrent_reads: 32
concurrent_writes: 32
concurrent_counter_writes: 32
concurrent_materialized_view_writes: 32
memtable_allocation_type: heap_buffers
index_summary_capacity_in_mb:
index_summary_resize_interval_in_minutes: 60
trickle_fsync: false
trickle_fsync_interval_in_kb: 10240
storage_port: 7000
ssl_storage_port: 7001
listen_address: localhost
start_native_transport: true
native_transport_port: 9042
start_rpc: false
rpc_address: localhost
rpc_port: 9160
rpc_keepalive: true
rpc_server_type: sync
thrift_framed_transport_size_in_mb: 15
incremental_backups: false
snapshot_before_compaction: false
auto_snapshot: true
tombstone_warn_threshold: 1000
tombstone_failure_threshold: 100000
column_index_size_in_kb: 64
batch_size_warn_threshold_in_kb: 5
batch_size_fail_threshold_in_kb: 50
compaction_throughput_mb_per_sec: 16
compaction_large_partition_warning_threshold_mb: 100
sstable_preemptive_open_interval_in_mb: 50
read_request_timeout_in_ms: 5000
range_request_timeout_in_ms: 10000
write_request_timeout_in_ms: 2000
counter_write_request_timeout_in_ms: 5000
cas_contention_timeout_in_ms: 1000
truncate_request_timeout_in_ms: 60000
request_timeout_in_ms: 10000
slow_query_log_timeout_in_ms: 500
cross_node_timeout: false
endpoint_snitch: SimpleSnitch
dynamic_snitch_update_interval_in_ms: 100
dynamic_snitch_reset_interval_in_ms: 600000
dynamic_snitch_badness_threshold: 0.1
request_scheduler: org.apache.cassandra.scheduler.NoScheduler
server_encryption_options:
    internode_encryption: none
    keystore: conf/.keystore
    keystore_password: cassandra
    truststore: conf/.truststore
    truststore_password: cassandra
client_encryption_options:
    enabled: false
    optional: false
    keystore: conf/.keystore
    keystore_password: cassandra
internode_compression: dc
inter_dc_tcp_nodelay: false
tracetype_query_ttl: 86400
tracetype_repair_ttl: 604800
gc_warn_threshold_in_ms: 1000
enable_user_defined_functions: false
enable_scripted_user_defined_functions: false
windows_timer_interval: 1
transparent_data_encryption_options:
    enabled: false
    chunk_length_kb: 64
    cipher: AES/CBC/PKCS5Padding
    key_alias: testing:1
    key_provider:
      - class_name: org.apache.cassandra.security.JKSKeyProvider
        parameters:
          - keystore: conf/.keystore
            keystore_password: cassandra
            store_type: JCEKS
            key_password: cassandra
EOF

# Set environment variables
log "Setting up environment variables..."
cat > /etc/environment << EOF
JAVA_HOME=$JAVA_HOME
CASSANDRA_HOME=/opt/cassandra
PATH=\$PATH:\$CASSANDRA_HOME/bin
EOF

# Create systemd service
log "Creating systemd service..."
cat > /etc/systemd/system/cassandra.service << EOF
[Unit]
Description=Apache Cassandra
After=network.target

[Service]
Type=forking
User=cassandra
Group=cassandra
ExecStart=/opt/cassandra/bin/cassandra -p /var/run/cassandra/cassandra.pid
ExecStop=/bin/kill -TERM \$MAINPID
PIDFile=/var/run/cassandra/cassandra.pid
StandardOutput=journal
StandardError=journal
SyslogIdentifier=cassandra
KillMode=process
Restart=on-failure
RestartSec=30

Environment=JAVA_HOME=$JAVA_HOME
Environment=CASSANDRA_HOME=/opt/cassandra
Environment=CASSANDRA_CONF=/opt/cassandra/conf

[Install]
WantedBy=multi-user.target
EOF

# Create PID directory
mkdir -p /var/run/cassandra
chown cassandra:cassandra /var/run/cassandra

# Configure JVM options
log "Configuring JVM options..."
JVM_OPTS="/opt/cassandra/conf/jvm.options"

# Check if jvm.options exists, if not create it
if [ ! -f "$JVM_OPTS" ]; then
    log "Creating jvm.options file..."
    # Get available memory
    TOTAL_MEM=$(free -m | awk 'NR==2{printf "%.0f", $2}')
    HEAP_SIZE=$((TOTAL_MEM / 4))

    if [ $HEAP_SIZE -gt 8192 ]; then
        HEAP_SIZE=8192
    elif [ $HEAP_SIZE -lt 512 ]; then
        HEAP_SIZE=512
    fi

    log "Setting heap size to ${HEAP_SIZE}M"

    # Create JVM options file
    cat > $JVM_OPTS << EOF
# Heap size
-Xms${HEAP_SIZE}M
-Xmx${HEAP_SIZE}M

# GC settings
-XX:+UseG1GC
-XX:+UnlockExperimentalVMOptions
-XX:+UseG1GC
-XX:G1RSetUpdatingPauseTimePercent=5
-XX:MaxGCPauseMillis=300
-XX:InitiatingHeapOccupancyPercent=70

# GC logging
-Xloggc:/var/log/cassandra/gc.log
-XX:+UseGCLogFileRotation
-XX:NumberOfGCLogFiles=10
-XX:GCLogFileSize=10M
-XX:+PrintGC
-XX:+PrintGCDetails
-XX:+PrintGCTimeStamps
-XX:+PrintGCApplicationStoppedTime
-XX:+PrintPromotionFailure
-XX:PrintFLSStatistics=1

# JVM settings
-ea
-XX:+UseThreadPriorities
-XX:ThreadPriorityPolicy=42
-XX:+HeapDumpOnOutOfMemoryError
-Xss256k
-XX:StringTableSize=1000003
-XX:+AlwaysPreTouch
-XX:-UseBiasedLocking
-XX:+UseTLAB
-XX:+ResizeTLAB
-XX:+UseNUMA
-XX:+PerfDisableSharedMem
-Djava.net.preferIPv4Stack=true

# Security
-Djava.security.egd=file:/dev/./urandom

# Netty
-Dio.netty.eventLoop.maxPendingTasks=65536
EOF
else
    # Backup existing file
    cp $JVM_OPTS ${JVM_OPTS}.backup
    
    # Get available memory
    TOTAL_MEM=$(free -m | awk 'NR==2{printf "%.0f", $2}')
    HEAP_SIZE=$((TOTAL_MEM / 4))

    if [ $HEAP_SIZE -gt 8192 ]; then
        HEAP_SIZE=8192
    elif [ $HEAP_SIZE -lt 512 ]; then
        HEAP_SIZE=512
    fi

    log "Setting heap size to ${HEAP_SIZE}M"

    # Update JVM options
    sed -i "s/^-Xms.*/-Xms${HEAP_SIZE}M/" $JVM_OPTS
    sed -i "s/^-Xmx.*/-Xmx${HEAP_SIZE}M/" $JVM_OPTS
fi

# Configure logback
log "Configuring logging..."
LOGBACK_CONF="/opt/cassandra/conf/logback.xml"
if [ -f "$LOGBACK_CONF" ]; then
    sed -i 's|<file>.*system.log</file>|<file>/var/log/cassandra/system.log</file>|' $LOGBACK_CONF
    sed -i 's|<file>.*debug.log</file>|<file>/var/log/cassandra/debug.log</file>|' $LOGBACK_CONF
else
    warn "logback.xml not found, skipping log configuration"
fi

# Set proper permissions
chown -R cassandra:cassandra /opt/cassandra
chmod +x /opt/cassandra/bin/*

# Configure firewall (if ufw is available)
if command -v ufw &> /dev/null; then
    log "Configuring firewall..."
    ufw allow 9042/tcp  # CQL port
    ufw allow 7000/tcp  # Inter-node communication
    ufw allow 7001/tcp  # SSL inter-node communication
    ufw allow 9160/tcp  # Thrift port (if needed)
fi

# Enable and start Cassandra service
log "Starting Cassandra service..."
systemctl daemon-reload
systemctl enable cassandra
systemctl start cassandra

# Wait for Cassandra to start
log "Waiting for Cassandra to start..."
sleep 30

# Check if Cassandra is running
if systemctl is-active --quiet cassandra; then
    log "Cassandra service is running"
else
    error "Cassandra service failed to start. Check logs: journalctl -u cassandra"
fi

# Test connection
log "Testing Cassandra connection..."
timeout 60 bash -c 'until /opt/cassandra/bin/cqlsh -e "DESCRIBE keyspaces;" 2>/dev/null; do sleep 2; done'

if [ $? -eq 0 ]; then
    log "Cassandra is ready and accepting connections!"
else
    warn "Cassandra might still be starting. Check status with: systemctl status cassandra"
fi

# Create keyspace for Lunox app
log "Creating Lunox keyspace..."
/opt/cassandra/bin/cqlsh -e "
CREATE KEYSPACE IF NOT EXISTS lunox 
WITH REPLICATION = {
    'class': 'SimpleStrategy',
    'replication_factor': 1
};
"

# Display connection info
log "=== Cassandra Setup Complete ==="
echo -e "${BLUE}Cassandra Version:${NC} $CASSANDRA_VERSION"
echo -e "${BLUE}Installation Path:${NC} /opt/cassandra"
echo -e "${BLUE}Data Directory:${NC} /var/lib/cassandra"
echo -e "${BLUE}Log Directory:${NC} /var/log/cassandra"
echo -e "${BLUE}CQL Port:${NC} 9042"
echo -e "${BLUE}Keyspace Created:${NC} lunox"
echo ""
echo -e "${GREEN}Commands:${NC}"
echo "  Start:   systemctl start cassandra"
echo "  Stop:    systemctl stop cassandra"
echo "  Status:  systemctl status cassandra"
echo "  CQL:     /opt/cassandra/bin/cqlsh"
echo "  Logs:    journalctl -u cassandra -f"
echo ""
echo -e "${GREEN}Connection String for Python:${NC}"
echo "  hosts=['127.0.0.1']"
echo "  port=9042"
echo "  keyspace='lunox'"

log "Setup completed successfully!"
