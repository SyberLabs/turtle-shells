#!/bin/sh
# Guest probe for T04/T05/T07. Any successful external reachability is a failure.
CANARY=${1:-http://127.0.0.1:9/}
FAIL=0
WGET="/bin/busybox wget"

try() {
  if $WGET -q -T 1 -O /dev/null "$1" 2>/dev/null; then
    echo "REACHED $1"
    FAIL=1
  fi
}

try http://1.1.1.1/
try http://169.254.169.254/latest/meta-data/
try http://10.0.0.1/
try "$CANARY"

if [ -S /var/run/docker.sock ] || [ -S /run/docker.sock ]; then
  echo DOCKER_SOCK
  FAIL=1
fi
if [ -n "$SSH_AUTH_SOCK" ]; then
  echo SSH_AUTH_SOCK
  FAIL=1
fi
if [ -S /tmp/.chrome-debug ] || [ -S /run/chrome-debug ]; then
  echo BROWSER_DEBUG
  FAIL=1
fi
if [ -r /proc/kcore ]; then
  echo HOST_PROC_KCORE
  FAIL=1
fi

exit $FAIL
