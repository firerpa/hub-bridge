#!/bin/bash
cd $(dirname $(dirname $(realpath $0)))
exec celery --app=tasks.celery worker -l INFO --pool prefork --without-gossip --without-mingle --beat $@
exit 10