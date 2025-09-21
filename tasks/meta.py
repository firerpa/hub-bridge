# Copyright 2022 rev1si0n (ihaven0emmail@gmail.com). All rights reserved.
# encoding=utf8
import os
import redis

from celery.schedules import crontab


class Celery:
    include = [
        "tasks.task",
    ]

    beat_schedule = {
"expire-peer-info": {
    "task": "tasks.task.expire",
    "schedule": crontab(minute="*/1"),
},
"expire-network": {
    "task": "tasks.task.expire_network",
    "schedule": crontab(minute="*/5"),
},
    }

    broker_url = os.environ["REDIS_URL"]
    result_backend = "rpc://"

    broker_connection_retry_on_startup = True
    redis = redis.StrictRedis.from_url(os.environ["REDIS_URL"])
    worker_log_format = "%(asctime)s: %(levelname)s %(message)s"

    worker_lost_wait = 120

    #worker_max_tasks_per_child = 1
    worker_prefetch_multiplier = 1
    worker_disable_rate_limits = False
    task_ignore_result = True

    worker_concurrency = 4

    task_compression = "zlib"
    result_compression = "zlib"

    task_serializer = "msgpack"
    result_serializer = "msgpack"
    accept_content = ["msgpack"]
    timezone = "Asia/Shanghai"
    enable_utc = True