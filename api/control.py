#!/usr/bin/env python3
import json
import requests

from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry


class ControlClient(object):
    def __init__(self, host, credential, pub):
        self.host = host
        s = requests.Session()
        retry = Retry(total=10, backoff_factor=0.5)
        s.mount("http://", HTTPAdapter(max_retries=retry))
        self.node = pub.split(":")[0]
        self.auth = credential
        self.s = s
    def post(self, path, **kwargs):
        res = self.request("post", path, **kwargs)
        return res["data"]
    def delete(self, path, **kwargs):
        res = self.request("delete", path, **kwargs)
        return res["data"]
    def get(self, path, **kwargs):
        res = self.request("get", path, **kwargs)
        return res["data"]
    def do_request_imp(self, method, path, **kwargs):
        url = "http://{}{}".format(self.host, path)
        data = kwargs.pop("data", None)
        data = json.dumps(data) if data else None
        kwargs.setdefault("headers", {})
        kwargs["headers"].update({"x-token": self.auth})
        kwargs["data"] = data
        res = self.s.request(method, url,
                             **kwargs)
        return res.json()
    def request(self, method, path, **kwargs):
        res = self.do_request_imp(method, path,
                                  **kwargs)
        return res
    def peer_info(self, node):
        uri = f"/peer/{node}"
        data = self.request("get", uri)
        return data
    def create_node(self, net):
        data = self.request("get", "/control/id/create")
        self.authorize_node(net, data["node_id"])
        return data
    def set_node_ip(self, net, node, ips):
        uri = f"/control/network/{net}/member/{node}"
        data = self.request("post", uri, data={"ipAssignments": ips})
        return data
    def network_info(self, net):
        uri = f"/control/network/{net}"
        data = self.request("get", uri)
        return data
    def delete_node(self, net, node):
        uri = f"/control/network/{net}/member/{node}"
        data = self.request("delete", uri)
        return data
    def authorize_node(self, net, node):
        uri = f"/control/network/{net}/member/{node}"
        data = self.request("post", uri, data={"authorized": True})
        return data
    def node_config_post(self, net, node, data):
        uri = f"/control/network/{net}/member/{node}"
        data = self.request("post", uri, data=data)
        return data
    def node_info(self, net, node):
        uri = f"/control/network/{net}/member/{node}"
        data = self.request("get", uri)
        return data
    def node_is_authorized(self, net, node):
        return self.node_info(net, node).get("authorized")
    def deauth(self, net, node):
        self.deauthorize_node(net, node)
        r = self.node_is_authorized(net, node)
        r = self.deauth(net, node) if r else True
        return r
    def deauthorize_node(self, net, node):
        uri = f"/control/network/{net}/member/{node}"
        data = self.request("post", uri, data={"authorized": False})
        return data
    def network_cfg(self, net, data):
        uri = f"/control/network/{net}"
        data = self.request("post", uri, data=data)
        return data
    def create_network(self, name):
        uri = f"/control/network/{self.node}______"
        data = self.request("post", uri, data={"name": name})
        return data
