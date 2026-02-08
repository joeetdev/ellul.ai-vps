#!/bin/bash
# Enforcer Logging Functions
# Logging and status output functions.

log() {
  echo "[$(date -Iseconds)] $1" >> "$LOG_FILE"
}
