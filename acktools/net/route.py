#!/usr/bin/python3

# Copyright (c) 2005-2022 Citrix Systems Inc.
# Copyright (c) 2023 Cloud Software Group, Inc.
#
# Redistribution and use in source and binary forms,
# with or without modification, are permitted provided
# that the following conditions are met:
#
# *   Redistributions of source code must retain the above
#     copyright notice, this list of conditions and the
#     following disclaimer.
# *   Redistributions in binary form must reproduce the above
#     copyright notice, this list of conditions and the
#     following disclaimer in the documentation and/or other
#     materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
# CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

import sys
import json

sys.path.append("/opt/xensource/packages/files/auto-cert-kit/pypackages")
import acktools
from acktools import utils


IP = "/sbin/ip"


class Route(object):
    """Class for representing a route object"""

    keys = ['dest', 'gw', 'mask', 'iface']

    def __init__(self, dest, gw, mask, iface):
        self.dest = dest
        self.gw = gw
        self.mask = mask
        self.iface = iface

    def get_dest(self):
        return self.dest

    def get_gw(self):
        return self.gw

    def get_mask(self):
        return self.mask

    def get_iface(self):
        return self.iface

    def get_record(self):
        rec = {}
        for key in self.keys:
            rec[key] = getattr(self, key)
        return rec


class RouteTable(object):
    """Class for representing a route table which constitutes 
    a collection of route objects."""

    def __init__(self, route_obj_list):
        self.routes = route_obj_list

    def get_routes(self, dest=None, mask=None, gw=None, iface=None):

        matching_routes = []

        for route in self.routes:
            if dest and route.dest != dest:
                continue
            if mask and route.mask != mask:
                continue
            if gw and route.gw != gw:
                continue
            if iface and route.iface != iface:
                continue
            else:
                # Route clearly matches the required fields
                matching_routes.append(route)

        return matching_routes

    def get_missing(self, rt):
        """Compare this route table with another passed in"""
        missing = []
        for route in self.get_routes():
            if not rt.get_routes(route.get_dest(),
                                 route.get_mask(),
                                 route.get_gw(),
                                 route.get_iface()):
                missing.append(route)
        return missing


def get_route_table():
    return json.loads(acktools.make_local_call([IP, '-j', 'route', 'show']))


def get_all_routes():
    """Return a list of route objects for all the routing
    entries currently found in the kernel"""

    route_list = []
    for route in get_route_table():
        if route['dst'] == 'default':
            route['dst'] = '0.0.0.0/0'

        if '/' in route['dst']:
            dst, cidr = route['dst'].split('/')
            cidr = int(cidr)
        else:
            dst, cidr = route['dst'], 0
        
        route_list.append(Route(dst,
                                route.get('gateway', '0.0.0.0'),
                                utils.cidr_to_netmask(cidr),
                                route['dev']))
    return route_list
