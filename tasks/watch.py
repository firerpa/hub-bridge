# Copyright 2022 rev1si0n (ihaven0emmail@gmail.com). All rights reserved.
# encoding=utf8
from pyinotify import (         WatchManager,
                                ProcessEvent,
                                Notifier,
                                IN_ATTRIB)
from json import dumps


class PeerStatusUpdate(ProcessEvent):
    def __init__(self, redis):
        super(PeerStatusUpdate, self).__init__()
        self.db = redis
    def process_IN_CREATE(self, event):
        return self.process_IN_ATTRIB(event)
    def process_IN_DELETE(self, event):
        return self.process_IN_ATTRIB(event)
    def process_IN_ATTRIB(self, event):
        pid = event.name.split(".")[0]
        task = dict(method="update_peer", args=[pid,])
        self.db.lpush("task", dumps(task))


if __name__ == "__main__":
    import redis
    import argparse

    argp = argparse.ArgumentParser()
    argp.add_argument("-p", "--path", required=True)
    argp.add_argument("-r", "--redis", required=True)
    args = argp.parse_args()

    wm = WatchManager()
    db = redis.StrictRedis.from_url(args.redis)
    watcher = Notifier(wm, PeerStatusUpdate(db))
    wm.add_watch(args.path, IN_ATTRIB)
    watcher.loop()