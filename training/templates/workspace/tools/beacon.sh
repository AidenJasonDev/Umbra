#!/bin/sh
# Harmless lab "beacon": records that it ran. Used by the persistence scenario.
date -u +%Y-%m-%dT%H:%M:%SZ >> "$(dirname "$0")/../logs/beacon.log"
