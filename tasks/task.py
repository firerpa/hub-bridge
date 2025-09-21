# Copyright 2022 rev1si0n (ihaven0emmail@gmail.com). All rights reserved.
# encoding=utf8
import json
import time
import logging
import threading

from jmespath import search as jsearch
from celery.signals import celeryd_init
from api.control import ControlClient
from api.models import *

from .celery import app

logger = logging.getLogger(__name__)

@app.task
def expire():
    for n in NetworkNode.select().where((NetworkNode.active > 0)
                        & (NetworkNode.active < (time.time() - 5*3600))):
        n.active = -1
        n.latency = -1
        n.addr = None
        logger.info(f"expire: {n.node_id}")
        n.save()


@app.task
def update_peer(peer):
    n = NetworkNode.get_or_none(
                    NetworkNode.node_id==peer)
    if n == None:
        return
    pub  = n.network.endpoint.pub
    host = n.network.endpoint.control_endpoint
    auth = n.network.endpoint.control_auth
    c = ControlClient(host, auth, pub)

    data = c.peer_info(peer)
    addr = jsearch("paths[?preferred==`true`].address|[0]", data)
    active = jsearch("max_by(paths, &max([lastReceive,lastSend])).lastSend",
                                                            data)
    n.network.endpoint.active = int(time.time())
    n.network.endpoint.save()
    n.latency = data.get("latency", -1)
    n.tunneled = data.get("tunneled", False)
    logger.info(f"peer: {peer},{addr},{n.latency}ms")
    n.addr = addr
    n.active = active / 1000
    n.save()


@app.task
def expire_network():
    for network in Network.select().where((Network.expire < time.time() - (3*86400))
                                        & (Network.expire != 0)
                                        & (Network.disabled == False)):
        network_disable.s(network.id).apply_async()


@app.task
def node_authorize(id):
    node = NetworkNode.get(NetworkNode.id==id)
    endpoint = node.network.endpoint
    api = ControlClient(endpoint.control_endpoint,
                        endpoint.control_auth,
                        endpoint.pub)
    logger.info(f"auth: {node.node_id}@{node.network.network_id}")
    config = dict(authorized=True, ipAssignments=[node.ip_v4,
                                                  node.ip_v6])
    api.node_config_post(node.network.network_id,
                         node.node_id,
                         config)


@app.task
def node_deauthorize(id):
    node = NetworkNode.get(NetworkNode.id==id)
    endpoint = node.network.endpoint
    api = ControlClient(endpoint.control_endpoint,
                        endpoint.control_auth,
                        endpoint.pub)
    logger.info(f"deauth: {node.node_id}@{node.network.network_id}")
    api.set_node_ip(node.network.network_id, node.node_id,
                                                      [])
    api.deauth(node.network.network_id,
                          node.node_id)


@app.task
def network_disable(id):
    network = Network.get(Network.id==id)
    network.disabled = True
    network.save()
    for node in network.nodes:
        node_deauthorize.s(node.id).apply_async()


@app.task
def network_enable(id):
    network = Network.get(Network.id==id)
    network.disabled = False
    network.save()
    for node in network.nodes:
        node_authorize.s(node.id).apply_async()


def pop_task():
    res = app.conf.redis.brpop("task",
                            timeout=0)
    task = json.loads(res[1])
    logger.info("got: %s" % task)
    func = globals().get(task["method"])
    func.s(*task["args"]).apply_async()
    loop = threading.Timer(0, pop_task)
    loop.daemon = True
    loop.start()


@celeryd_init.connect
def task_loop(sender=None, conf=None,
                                **kwargs):
    loop = threading.Thread(target=pop_task,
                                daemon=True)
    loop.start()