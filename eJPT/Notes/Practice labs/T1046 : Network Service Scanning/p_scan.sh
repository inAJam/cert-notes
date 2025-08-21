#!/bin/bash

# Usage: ./scanner.sh <target_ip> <start_port> <end_port>

target=$1
start_port=$2
end_port=$3

echo "Scanning $target from port $start_port to $end_port..."

for ((port=start_port; port<=end_port; port++)); do
  timeout 1 bash -c "echo > /dev/tcp/$target/$port" 2>/dev/null
  if [ $? -eq 0 ]; then
    echo "Port $port is OPEN"
  fi
done