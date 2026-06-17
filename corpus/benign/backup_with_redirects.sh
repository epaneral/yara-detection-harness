#!/bin/bash
# Legitimate backup job: stderr/stdout redirection that superficially resembles ">&".
LOG=/var/log/backup.log
tar czf /backups/data.tgz /srv/data >& "$LOG" 2>&1
echo "backup complete" >> "$LOG"
