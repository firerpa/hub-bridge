#!/usr/bin/env python3
import time

from peewee import *
from playhouse.shortcuts import model_to_dict

database = SqliteDatabase("/data/database.db", pragmas={
                                        "foreign_keys": "1",
                                        "locking_mode": "NORMAL",
                                        "journal_mod": "wal",
                                        "synchronous": "NORMAL"})

class BaseDatabaseModel(Model):
    class Meta:
        database = database
    def to_dict(self, **kwargs):
        ret = model_to_dict(self, **kwargs)
        return ret


class NetworkEndpoint(BaseDatabaseModel):
    control_endpoint= CharField()
    control_auth    = CharField()
    s               = CharField()
    s_v6            = CharField(null=True)
    s_tf            = CharField(default="0.0.0.0/0") # TCP fallback relay
    pub             = CharField(max_length=512)
    active          = BigIntegerField(default=0)
    created         = BigIntegerField(default=0)
    online          = BooleanField(default=True)


class Network(BaseDatabaseModel):
    token           = CharField(unique=True)
    network_id      = CharField(unique=True)
    endpoint        = ForeignKeyField(NetworkEndpoint, backref="networks")

    network         = CharField(null=True)
    network_v6      = CharField(null=True)

    ald             = BooleanField(default=True)  # allowDefault
    ftr             = BooleanField(default=False) # force tcp relay
    atf             = BooleanField(default=False) # auto tcp fallback relay
    alg             = BooleanField(default=True)  # allowGlobal

    expire          = BigIntegerField(default=0)
    created         = BigIntegerField(default=time.time)
    disabled        = BooleanField(default=False)
    limit           = BigIntegerField(default=0)


class NetworkNode(BaseDatabaseModel):
    network         = ForeignKeyField(Network, backref="nodes")
    comment         = CharField(null=True)
    client_id       = CharField(null=True)

    token           = CharField(unique=True)
    node_id         = CharField(unique=True)
    ip_v4           = CharField(null=True)
    ip_v6           = CharField(null=True)

    pub             = CharField(max_length=320)
    pri             = CharField(max_length=320)

    ftr             = BooleanField(default=False)
    atf             = BooleanField(default=False)

    latency         = IntegerField(default=0)
    tunneled        = BooleanField(default=False)

    addr            = CharField(null=True)
    active          = BigIntegerField(default=0)
    attached        = BigIntegerField(default=0)
    created         = BigIntegerField(default=time.time)


class NetworkNodeCfg(BaseDatabaseModel):
    networknode     = ForeignKeyField(NetworkNode, backref="cfgs")
    name            = CharField(max_length=255)
    value           = CharField(max_length=8192)
    class Meta:
        indexes = (
            (("networknode_id", "name"), True),
        )