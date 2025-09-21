#!/bin/bash
if [ ! -d /data/ztnet ]; then
echo "Run setup.sh first to initialize this node"
exit 100
fi

source /data/environment

export REDIS=$(($((RANDOM))+10000))
export REDIS_URL=redis://127.0.0.1:${REDIS}/0

cat <<EOL >/var/run/redis.conf
bind 127.0.0.1
port ${REDIS}
pidfile /var/run/redis.pid
protected-mode yes
tcp-backlog 4096
timeout 7200
tcp-keepalive 300
daemonize no
supervised no

loglevel notice
logfile ""
databases 16
always-show-logo no

dir "/data"

save ""

stop-writes-on-bgsave-error yes
rdbcompression yes
rdbchecksum yes

# nopass (localhost instance)
slave-serve-stale-data yes
slave-read-only yes
slave-priority 100

maxclients 4096
# maxmemory 4294967296
# maxmemory-policy noeviction
lazyfree-lazy-eviction no
lazyfree-lazy-expire no
lazyfree-lazy-server-del no
slave-lazy-flush no
appendonly yes
appendfilename "redis.aof"
appendfsync everysec
no-appendfsync-on-rewrite no
auto-aof-rewrite-percentage 100
auto-aof-rewrite-min-size 64mb
aof-load-truncated yes
aof-use-rdb-preamble no
lua-time-limit 5000
slowlog-max-len 128
latency-monitor-threshold 0
hash-max-ziplist-entries 512
hash-max-ziplist-value 64
list-max-ziplist-size -2
list-compress-depth 0
set-max-intset-entries 512
zset-max-ziplist-entries 128
zset-max-ziplist-value 64
hll-sparse-max-bytes 3000
activerehashing yes
client-output-buffer-limit normal 0 0 0
client-output-buffer-limit slave 256mb 64mb 60
client-output-buffer-limit pubsub 32mb 8mb 60
hz 10
aof-rewrite-incremental-fsync yes
EOL

cat <<EOL >/var/run/supervisord.conf
[unix_http_server]
file=/var/run/service.sock
chmod=0700

[rpcinterface:supervisor]
supervisor.rpcinterface_factory = supervisor.rpcinterface:make_main_rpcinterface

[supervisord]
childlogdir=/var/run
logfile=/proc/self/fd/1
logfile_maxbytes=0
loglevel=info
nodaemon=true
silent=true
pidfile=/var/run/service.pid
user=root

[supervisorctl]
serverurl=unix:///var/run/service.sock

[program:bridge]
directory               = /data/ztnet
command                 = bridge -p${BRIDGE}
autostart               = true
autorestart             = true
redirect_stderr         = true
stdout_logfile          = /dev/stdout
stdout_logfile_maxbytes = 0
stdout_logfile_backups  = 0

[program:api]
directory               = /service
command                 = python3 -u -m api --port=${API}
autostart               = true
autorestart             = true
redirect_stderr         = true
stdout_logfile          = /dev/stdout
stdout_logfile_maxbytes = 0
stdout_logfile_backups  = 0

[program:redis]
directory               = /service
command                 = redis-server /var/run/redis.conf
autostart               = true
autorestart             = true
redirect_stderr         = true
stdout_logfile          = /dev/stdout
stdout_logfile_maxbytes = 0
stdout_logfile_backups  = 0

[program:watch]
directory               = /service/tasks
command                 = python3 -u watch.py -r redis://127.0.0.1:${REDIS}/0 -p /data/ztnet/
autostart               = true
autorestart             = true
redirect_stderr         = true
stdout_logfile          = /dev/stdout
stdout_logfile_maxbytes = 0
stdout_logfile_backups  = 0

[program:task]
directory               = /service
command                 = sh tasks/start.sh
autostart               = true
autorestart             = true
redirect_stderr         = true
stdout_logfile          = /dev/stdout
stdout_logfile_maxbytes = 0
stdout_logfile_backups  = 0
EOL

exec supervisord -c /var/run/supervisord.conf
