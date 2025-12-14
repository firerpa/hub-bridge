#!/usr/bin/env python3
import os
import re
import time
import json
import tornado.web
import tornado.ioloop
import tornado.httpserver

import logging
import asyncio
import random
import traceback

from collections import OrderedDict
from tornado import httputil
from tornado.web import Application
from tornado.options import define, options
from tornado.web import HTTPError
from tornado.ioloop import IOLoop

from ipaddress import IPv6Network, IPv4Network, ip_address, ip_network
from top import decrypt_key_with_private_key, aes_decrypt, aes_encrypt

from tasks.task import network_disable, network_enable

from .control import ControlClient
from .models import *

logger = logging.getLogger()

errors = {}
# ztnet
errors["401001"] = "Invalid super secret"
errors["404001"] = "No such service token"
errors["404002"] = "No such node token"
errors["400006"] = "This token is bounded to another client"
errors["400007"] = "Duplicate ip address"
errors["400008"] = "The network address for this token is not set"
errors["400009"] = "Maximum allowed nodes exceeded"
errors["400010"] = "Network is not configured"
errors["400011"] = "Invalid ip address"
errors["400012"] = "Exceed max node config entries"
errors["400013"] = "Unable to set configuration for attached node"
errors["400014"] = "Value cannot contain spaces"
errors["400015"] = "Network is already configured"
errors["400016"] = "Network too small or invalid"
errors["400018"] = "Network is disabled"
errors["400019"] = "Network is already disabled"


cur_dir = os.path.dirname(__file__)

default_v4 = "10.5.0.0/16"
default_v6 = "fd00:123:123::/80"


class ArgDefaultMarker:
    """ ArgDefaultMarker """


def ignore_exception(value):
    def wraps(func):
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception:
                return value
        return wrapper
    return wraps


class HttpServiceManager(object):
    def __init__(self, bind="0.0.0.0", port=9000):
        self.handlers = OrderedDict()
        self.static = os.path.join(cur_dir, "static")
        self.template = os.path.join(cur_dir, "html")
        self.bind = bind
        self.port = port

    def add_handler(self, route, handle, *args):
        self.handlers[route] = (route, handle, *args)

    def start_server(self):
        kwargs = {}
        kwargs["debug"] = False
        kwargs["template_path"] = self.template
        kwargs["compiled_template_cache"] = True
        kwargs["static_path"] = self.static
        http = Application(self.handlers.values(),
                                        **kwargs)
        server = tornado.httpserver.HTTPServer(http)
        server.bind(self.port, address=self.bind)
        server.start (0)
        loop = asyncio.get_event_loop()
        self.ioloop = IOLoop.current()
        self.ioloop.start()


class BaseHttpService(tornado.web.RequestHandler):
    def throw(self, status, error=None,
                                message=None):
        message = message or errors.get(error)
        raise HTTPError(status, reason=error,
                        log_message=message)

    def set_default_headers(self):
        self._headers.pop("Date", None)
        self._headers.pop("Content-Type", None)
        self._headers.pop("Server", None)

    def initialize(self, skey=None, secret=None):
        s = self.get_query_argument("s")
        ekey = decrypt_key_with_private_key(skey, s)
        body = aes_decrypt(ekey, self.request.body)
        data = json.loads(body)
        self.api_ekey = ekey
        self.api_args = data.get("args", {})
        self.api_name = data.get("api")
        self.super_secret = secret

    def write_error(self, status, exc_info=None,
                                        **kwargs):
        error = self._reason
        self._reason = httputil.responses.get(status, "Unknown")
        try:
            self.tell({"status": status, "error": error,
                     "message": exc_info[1].log_message})
        except AttributeError:
            traceback.print_exception(*exc_info)
            self.tell({"status": 500, "error": "500000",
                     "message": "Internal Server Error"})

    def __init__(self, *args, **kwargs):
        super(BaseHttpService, self).__init__(*args, **kwargs)
        self.ioloop = tornado.ioloop.IOLoop.current()

    def r_string(self, n):
        return "".join(random.sample("abcdefhiklmnors"\
                                     "tuvwxz0123456789", n))

    async def call_sync_async(self, func, *args):
        return await self.ioloop.run_in_executor(None,
                                        func, *args)

    def timestamp(self):
        return int(time.time())

    def tell(self, data, sign=True):
        data.setdefault("status", 0)
        data.setdefault("message", "OK")
        data = aes_encrypt(self.api_ekey, json.dumps(data).encode())
        self.write(data)

    async def comm(self, *args):
        method = self.request.method.lower()
        call = getattr(self, f"http_{method}",
                                self.default)
        r = await self.call_sync_async(call,
                                    *args)
        self.tell(r)

    async def get(self, *args):
        await self.comm(*args)
    async def delete(self, *args):
        await self.comm(*args)
    async def post(self, *args):
        await self.comm(*args)
    async def patch(self, *args):
        await self.comm(*args)
    async def put(self, *args):
        await self.comm(*args)

    def http_get(self, *args):
        self.throw(501)
    def http_post(self, *args):
        self.throw(501)
    def http_delete(self, *args):
        self.throw(501)
    def http_patch(self, *args):
        self.throw(501)
    def http_put(self, *args):
        self.throw(501)

    def default(self, *args):
        self.throw(404)
    def head(self, *args, **kwargs):
        self.set_status(200)


class TopBaseUtilService(BaseHttpService):
    def get_node_by_token_no_raise(self, token):
        r = NetworkNode.select().where(NetworkNode.token==token
                                                ).get_or_none()
        return r
    def get_node_by_token_with_cid(self, token, cid):
        r = self.get_node_by_token(token)
        self.check_node_belong_cid(r, cid)
        return r
    def get_node_by_token(self, token):
        r = NetworkNode.select().where(NetworkNode.token==token
                                                ).get_or_none()
        r or self.throw(404, "404002")
        return r
    def check_node_belong_cid(self, r, cid):
        condition = r.client_id and cid != r.client_id
        condition and self.throw(400, "400006")
    def check_node_ip46_set(self, r):
        condition = r.ip_v4 and r.ip_v6
        condition or self.throw(400, "400008")
    def get_net_by_token(self, token):
        r = Network.select().where(Network.token==token
                                   ).get_or_none()
        r or self.throw(404, "404001")
        return r
    def convert_value(self, val):
        s = json.dumps(val, separators=(",", ":"))
        return val if isinstance(val, str) else s
    def check_net_node_limit(self, r):
        condition = r.nodes.count() <= r.limit # allow 1 more
        condition or self.throw(400, "400009")
    def check_net_disabled(self, r, e="400018"):
        condition = not r.disabled
        condition or self.throw(400, "400018")
    def check_network_configured(self, r):
        condition = r.network and r.network_v6
        condition or self.throw(400, "400010")
    def check_network_not_configured(self, r):
        condition = r.network or r.network_v6
        condition and self.throw(400, "400015")
    def check_value_contains_space(self, value):
        condition = re.search("\s", self.convert_value(value))
        condition and self.throw(400, "400014")
    def check_config_client_attached(self, r):
        condition = r.client_id
        condition and self.throw(400, "400013")
    def check_node_max_config_entries(self, r, count, inc=1):
        condition = r.cfgs.count() + inc > count
        condition and self.throw(400, "400012")
    def get_network_node(self, network, node):
        n = self.get_net_by_token(network)
        r = NetworkNode.select().where((NetworkNode.token==node)
                        & (NetworkNode.network==n)).get_or_none()
        r or self.throw(404, "404002")
        return r
    def get_ctl_by_node(self, r):
        pub  = r.network.endpoint.pub
        host = r.network.endpoint.control_endpoint
        auth = r.network.endpoint.control_auth
        return ControlClient(host, auth, pub)
    def get_ctl_by_net(self, r):
        pub  = r.endpoint.pub
        host = r.endpoint.control_endpoint
        auth = r.endpoint.control_auth
        return ControlClient(host, auth, pub)
    def check_ip_in_network(self, ip, network):
        addr = self.to_ipaddress(ip)
        r = addr in ip_network(network)
        r or self.throw(400, "400011", f"Invalid ip address {ip}")
    def check_ip_duplicate(self, ip, net, token):
        r = net.nodes.where(NetworkNode.token != token
                               ).where((NetworkNode.ip_v4==ip) \
                                     | (NetworkNode.ip_v6==ip)).exists()
        r and self.throw(400, "400007", f"Duplicate ip address {ip}")
    @ignore_exception(ip_address("0.0.0.0"))
    def to_ipaddress(self, ip):
        return ip_address(ip)
    def node_to_dict(self, r):
        return r.to_dict(exclude=[NetworkNode.network,
                                  NetworkNode.attached,
                                  NetworkNode.created,
                                  NetworkNode.id,
                                  NetworkNode.ftr,
                                  NetworkNode.atf,
                                  NetworkNode.tunneled,
                                  NetworkNode.node_id,
                                  NetworkNode.pub,
                                  NetworkNode.pri])
    def cfg_to_dict(self, r):
        return r.to_dict(exclude=[NetworkNodeCfg.networknode,
                                  NetworkNodeCfg.id])
    def network_to_dict2(self, r):
        return r.to_dict(exclude=[   Network.endpoint,
                                     Network.ald,
                                     Network.ftr,
                                     Network.atf,
                                     Network.alg,
                                     Network.network_id])
    def network_to_dict(self, r):
        return r.to_dict(exclude=[Network.id,
                                     Network.token,
                                     Network.endpoint,
                                     Network.ald,
                                     Network.ftr,
                                     Network.atf,
                                     Network.alg,
                                     Network.network_id,
                                     Network.created,])
    @ignore_exception(0)
    def num_net_addresses(self, network):
        net = ip_network(network)
        return net.num_addresses
    def check_netrange_big_enough(self, network):
        if self.num_net_addresses(network) < 256:
            self.throw(400, "400016", "Network too small or invalid {}"
                                      .format(network))


class TopSpecificNodeService(TopBaseUtilService):
    def api_getNodeInfo(self):
        node = self.get_api_argument("node")
        network = self.get_api_argument("network")
        n = self.get_network_node(network, node)
        return dict(data=self.node_to_dict(n))
    def api_deleteNode(self):
        node = self.get_api_argument("node")
        network = self.get_api_argument("network")
        n = self.get_network_node(network, node)
        c = self.get_ctl_by_node(n)
        c.deauth(n.network.network_id,
                                    n.node_id)
        c.delete_node(n.network.network_id,
                                    n.node_id)
        n.delete_instance(recursive=True)
        return dict(message="OK")


class TopSpecificNodeIPService(TopBaseUtilService):
    def api_setNodeStaticIp(self):
        ifconfig = []
        node = self.get_api_argument("node")
        network = self.get_api_argument("network")
        n = self.get_network_node(network, node)
        c = self.get_ctl_by_node(n)
        self.check_net_disabled(n.network)
        self.check_network_configured(n.network)
        v4 = self.get_api_argument("v4", None)
        v6 = self.get_api_argument("v6", None)
        # random ip address
        v4 = v4 if v4 != "random" else self.random_v4(n)
        v6 = v6 if v6 != "random" else self.random_v6(n)
        self.check_ip_in_network(v4, n.network.network)
        self.check_ip_in_network(v6, n.network.network_v6)
        self.check_ip_duplicate(v4, n.network, n.token)
        self.check_ip_duplicate(v6, n.network, n.token)
        v4 and ifconfig.append(v4)
        v6 and ifconfig.append(v6)
        res = c.set_node_ip(n.network.network_id,
                                 n.node_id, ifconfig)
        data = {}
        n.ip_v4 = v4
        n.ip_v6 = v6
        n.save()
        data["ips"] = res["ipAssignments"]
        return dict(data=data)
    def random_v6(self, r):
        net = ip_network(r.network.network_v6)
        return self.find_ip(net, r)
    def random_v4(self, r):
        net = ip_network(r.network.network)
        return self.find_ip(net, r)
    def find_ip(self, net, node):
        while True:
            ip = net[random.randint(5, net.num_addresses - 1)]
            r = node.network.nodes.where((NetworkNode.ip_v4==ip) \
                                    | (NetworkNode.ip_v6==ip)).exists()
            if not r:
                return str(ip)


class TopSpecificNodeCommentService(TopBaseUtilService):
    def api_setNodeComment(self):
        node = self.get_api_argument("node")
        network = self.get_api_argument("network")
        comment = self.get_api_argument("comment")
        node = self.get_network_node(network, node)
        node.comment = comment
        node.save()
        data = dict(data=self.node_to_dict(node))
        return data


class TopSpecificNodeConfigService(TopBaseUtilService):
    def store_config(self, node, name, value):
        meta = {}
        meta["name"] = name
        meta["value"] = self.convert_value(value)
        self.check_value_contains_space(meta["value"])
        r, _ = NetworkNodeCfg.get_or_create(networknode=node,
                                            name=meta["name"],
                                            defaults=meta)
        r.name = meta["name"]
        r.value = meta["value"]
        r.save()
    def api_putNodeConfig(self):
        node = self.get_api_argument("node")
        network = self.get_api_argument("network")
        data = self.get_api_argument("configs")
        node = self.get_network_node(network, node)
        self.check_config_client_attached(node)
        self.check_node_max_config_entries(node, 32, inc=len(data))
        list([self.check_value_contains_space(v) for v in data.values()])
        list([self.store_config(node, n, v) for n, v in data.items()])
        return dict(message="OK")
    def api_setNodeConfig(self):
        node = self.get_api_argument("node")
        network = self.get_api_argument("network")
        name = self.get_api_argument("name")
        value = self.get_api_argument("value")
        node = self.get_network_node(network, node)

        self.check_config_client_attached(node)
        self.check_node_max_config_entries(node, 32, inc=1)
        self.store_config(node, name, value)
        return dict(message="OK")
    def api_delNodeConfig(self):
        node = self.get_api_argument("node")
        network = self.get_api_argument("network")
        name = self.get_api_argument("name")
        node = self.get_network_node(network, node)
        r = NetworkNodeCfg.get_or_none(NetworkNodeCfg.networknode==node,
                                       NetworkNodeCfg.name==name)
        r and r.delete_instance()
        return dict(message="OK")
    def api_listNodeConfig(self):
        node = self.get_api_argument("node")
        network = self.get_api_argument("network")
        node = self.get_network_node(network, node)
        cfgs = [self.cfg_to_dict(c) for c in node.cfgs]
        return dict(data=cfgs)


class TopNodeAttachService(TopBaseUtilService):
    def delete_info(self, r, c):
        self.check_node_belong_cid(r, c)
        r.latency                       = -1
        r.addr                          = None
        r.client_id                     = None
        r.active                        = -1
        r.save()
        return dict(message="Detached OK")
    def api_nodeDetach(self):
        token = self.get_api_argument("token")
        c = self.get_api_argument("client_id", None)
        n = dict(message="Token not exist")
        r = self.get_node_by_token_no_raise(token)
        data = self.delete_info(r, c) if r else n
        return data
    def api_nodeAttach(self):
        token = self.get_api_argument("token")
        c = self.get_api_argument("client_id")
        r = self.get_node_by_token_with_cid(token, c)
        self.check_node_ip46_set(r)
        self.check_net_disabled(r.network)
        r.client_id = c
        r.attached = self.timestamp()
        r.save()
        data = {}
        data["nid"] = r.network.network_id
        ev6 = r.network.endpoint.s_v6
        data["endpoints"] = [r.network.endpoint.s]
        ev6 and data["endpoints"].append(ev6)
        data["spb"] = r.network.endpoint.pub
        data["mpb"] = r.pub
        data["mpr"] = r.pri
        data["tfr"] = r.network.endpoint.s_tf
        data["ftr"] = r.ftr or r.network.ftr
        data["atf"] = r.atf or r.network.atf
        data["ald"] = r.network.ald
        data["alg"] = r.network.alg
        data["cfg"] = [[c.name, c.value] for c in r.cfgs]
        return data


class TopNodeService(TopBaseUtilService):
    def api_listNode(self):
        network = self.get_api_argument("network")
        net = self.get_net_by_token(network)
        page = int(self.get_api_argument("page", 0))
        size = int(self.get_api_argument("size", 10))
        records = net.nodes.select().order_by(NetworkNode.id
                                       ).paginate(page, size)
        data = {}
        data["page"] = page
        data["size"] = size
        nodes = [self.node_to_dict(i) for i in records]
        data["total"] = net.nodes.count()
        data["data"] = nodes
        return data
    def api_createNode(self):
        network = self.get_api_argument("network")
        net = self.get_net_by_token(network)
        self.check_net_disabled(net)
        self.check_net_node_limit(net)
        c = self.get_ctl_by_net(net)
        comment = self.get_api_argument("comment", "")
        keys = c.create_node(net.network_id)
        nid = self.get_api_argument("token", "i" + self.r_string(20))
        node = NetworkNode.create(network=net,
                                      token=nid,
                                      **keys)
        node.comment = comment
        node.save()
        info = self.node_to_dict(node)
        return dict(data=info)


class TopNetworkService(TopBaseUtilService):
    def add_route(self, cfg, r):
        r and cfg["routes"].append({"target":r,"via":None})
    def add_pool(self, cfg, r):
        rang = self.range_ip(r)
        r and cfg["ipAssignmentPools"].append(rang)
    @ignore_exception(None)
    def range_ip(self, network):
        net = ip_network(network)
        data = {}
        data["ipRangeStart"] = str(net[0])
        data["ipRangeEnd"] = str(net[-1])
        return data
    @ignore_exception(None)
    def net_v6(self, network):
        net = IPv6Network(network)
        return str(net)
    @ignore_exception(None)
    def net_v4(self, network):
        net = IPv4Network(network)
        return str(net)
    def api_setupNetwork(self):
        ntcfg = {}
        network = self.get_api_argument("network")
        net = self.get_net_by_token(network)
        self.check_network_not_configured(net)
        v4 = self.get_api_argument("v4", default_v4)
        v6 = self.get_api_argument("v6", default_v6)
        ntcfg["ipAssignmentPools"] = []
        self.check_netrange_big_enough(v4)
        self.check_netrange_big_enough(v6)
        self.add_pool(ntcfg, v4)
        self.add_pool(ntcfg, v6)
        net.network_v6 = self.net_v6(v6)
        net.network = self.net_v4(v4)
        ntcfg["routes"] = []
        self.add_route(ntcfg, v4)
        self.add_route(ntcfg, v6)
        ntcfg["v4AssignMode"] = None
        ntcfg["v6AssignMode"] = None
        ntcfg["enableBroadcast"] = False
        ntcfg["private"] = True
        c = self.get_ctl_by_net(net)
        c.network_cfg(net.network_id, ntcfg)
        net.save()
        data = self.network_to_dict(net)
        return dict(data=data)
    def api_getNetworkInfo(self):
        network = self.get_api_argument("network")
        net = self.get_net_by_token(network)
        data = self.network_to_dict(net)
        data["online"] = net.nodes.where(
                    NetworkNode.latency > 0).count()
        data["total"] = net.nodes.count()
        return dict(data=data)


class TopSuperviseService(TopBaseUtilService):
    def check_super_secret(self):
       r = self.get_api_argument("secret") == self.super_secret
       r or self.throw(401, "401001")
    def api_createNetwork(self):
        self.check_super_secret()
        endpoint = NetworkEndpoint.select().order_by(
                                        fn.Random()).get()
        token = self.get_api_argument("token", "n" + self.r_string(20))
        api = ControlClient(endpoint.control_endpoint,
                            endpoint.control_auth, endpoint.pub)
        info = api.create_network(token)
        network = Network.create(       network_id=info["nwid"],
                                        token=token,
                                        endpoint=endpoint,
                                        atf=True,
                                        expire=3471264000, # 2080-01-01
                                        limit=65535,)
        network.save()
        data = dict()
        data["token"] = token
        data["limit"] = network.limit
        return dict(data=data)
    def api_disableNetwork(self):
        # TODO: race condition
        self.check_super_secret()
        network = self.get_api_argument("network")
        net = self.get_net_by_token(network)
        self.check_net_disabled(net, e="400019")
        network_disable.s(net.id).apply_async()
        data = dict()
        data["token"] = network
        return dict(data=data)
    def api_enableNetwork(self):
        # TODO: race condition
        self.check_super_secret()
        network = self.get_api_argument("network")
        net = self.get_net_by_token(network)
        network_enable.s(net.id).apply_async()
        data = dict()
        data["token"] = network
        return dict(data=data)
    def api_listNetwork(self):
        self.check_super_secret()
        page = int(self.get_api_argument("page", 0))
        size = int(self.get_api_argument("size", 10))
        records = Network.select().order_by(Network.id
                                       ).paginate(page, size)
        data = {}
        data["page"] = page
        data["size"] = size
        nets = [self.network_to_dict2(i) for i in records]
        data["total"] = Network.select().count()
        data["data"] = nets
        return data


class SingleEndPointAPI(TopNodeAttachService, TopNodeService,
                        TopSpecificNodeService, TopSpecificNodeIPService,
                        TopSpecificNodeCommentService, TopSpecificNodeConfigService,
                        TopNetworkService, TopSuperviseService, BaseHttpService):
    def http_post(self):
        return getattr(self, f"api_{self.api_name}",
                                self.api_default)()
    def get_api_argument(self, name, default=ArgDefaultMarker()):
        result = self.api_args.get(name) or default
        if isinstance(result, ArgDefaultMarker): self.throw(400,
                          message="Missing argument %s" % name)
        return result
    def api_default(self, *args):
        self.throw(501)


def main():
    define("port", default=9000, type=int)
    define("bind", default="0.0.0.0", type=str)
    define("secret", type=str, default=os.environ.get("SECRET"))
    define("skey", type=str, default=os.environ.get("SKEY"))
    tornado.options.parse_command_line()

    NetworkEndpoint.create_table()

    Network.create_table()
    NetworkNode.create_table()
    NetworkNodeCfg.create_table()

    http = HttpServiceManager(options.bind, options.port)
    http.add_handler("/", SingleEndPointAPI, dict(skey=options.skey,
                                            secret=options.secret))
    logging.getLogger().setLevel(logging.DEBUG)
    http.start_server()


if __name__ == "__main__":
    main()
