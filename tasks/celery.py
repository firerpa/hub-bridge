# Copyright 2022 rev1si0n (ihaven0emmail@gmail.com). All rights reserved.
# encoding=utf8
from celery import Celery

app = Celery("tasks")
app.config_from_object("tasks.meta.Celery")
app.autodiscover_tasks()