#!/usr/bin/python

# Copyright (c) Citrix Systems Inc.
# All rights reserved.
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

import acktools
from acktools import utils

ROUTE_CLI = "/sbin/route"

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

def get_route_table():
    return acktools.make_local_call([ROUTE_CLI,'-n'])    

def get_all_routes():
    """Return a list of route objects for all the routing
    entries currently found in the kernel"""

    output = get_route_table()
    lines = output.split('\n')
    
    if lines[0] != "Kernel IP routing table":
        raise Exception("Error! Unexpected format: '%s'" % output)

    # Join the table lines
    route_table = "\n".join(lines[1:])    

    # Parse the table to produce a list of recs
    recs = utils.cli_table_to_recs(route_table)

    route_list = []
    for rec in recs:

        # Use keys from route table output
        route = Route(rec['Destination'],
                      rec['Gateway'],
                      rec['Genmask'],
                      rec['Iface'],
                     )

        route_list.append(route)

    return route_list
