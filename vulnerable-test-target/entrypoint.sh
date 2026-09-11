#!/bin/bash
set -e
service nginx start
exec /usr/sbin/sshd -D
