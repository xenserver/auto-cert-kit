"""
XenAPI Mock Lib for unittest

XenAPI requires a live session to XenServer hence needs to be mocked
while running unit tests.
"""

import mock
import random

class XenAPIObjectMock(object):
    """Base class for XenAPI object models"""

    USED_SUFFIXES = []

    @classmethod
    def genIdentity(cls, clsname=''):
        """A Opaque generator"""
    
        suffix = '_%d' % random.randint(0, 9999999)
        while suffix in cls.USED_SUFFIXES:
            suffix = '_%d' % random.randint(0, 9999999)
        cls.USED_SUFFIXES.append(suffix)
    
        return ('Opaque: %sOpaque%s' % (clsname, suffix), \
                '%sUUID%s' % (clsname, suffix))

    def __init__(self):
        self.__opaque, self.__uuid = self.__class__.genIdentity(self.__class__.__name__)

    @property
    def opaque(self):
        return self.__opaque

    @property
    def uuid(self):
        return self.__uuid


class Session(XenAPIObjectMock):
    """Session data structure for XenAPI Session mock"""

    __INSTANCE = None

    @classmethod
    def instance(cls):
        # session needs to be the same while test runs throughly.
        if Session.__INSTANCE is None:
            Session.__INSTANCE = Session()
        return Session.__INSTANCE

    def __init__(self, hosts=2, networks=1):
        super(Session, self).__init__()
        self.__networks = [Network(i) for i in xrange(networks)]
        self.__pool = Pool(hosts, self.__networks)
        self.__xenapi = XenapiMock()

    @property
    def xenapi(self):
        return self.__xenapi

    @property
    def handle(self):
        return self.__opaque

    @property
    def pools(self):
        return [self.__pool]

    @property
    def hosts(self):
        return self.__pool.hosts

    @property
    def networks(self):
        return self.__networks


class Network(XenAPIObjectMock):
    """Network data structure for XenAPI Network mock"""

    def __init__(self, netid, bridge="xenbr"):
        super(Network, self).__init__()
        self.__name = "NETWORK_%d" % netid
        self.__bridge = "%s%d" % (bridge, netid)
        self.__pifs = []

    @property
    def bridge(self):
        return self.__bridge

    @property
    def PIFs(self):
        return self.__pifs

    def addPIF(self, pif):
        self.__pifs.append(pif)


class Bond(Network):
    """Bond network data structure for XenAPI Bond mock"""

    def __init__(self, pifs, netid, bridge="xapi"):
        super(Bond, self).__init__(netid, bridge)
        self.__name = "Bond_%d" % netid
        self.pifs = pifs


class PIF(XenAPIObjectMock):
    """PIF data structure for XenAPI PIC mock"""

    def __init__(self, host, network, devid):
        super(PIF, self).__init__()
        self.__plugged = True
        self.__enabled = True
        self.__host = host
        self.__network = network
        self.__device = "eth%d" % devid

    @property
    def plugged(self):
        return  self.__plugged

    @plugged.setter
    def plugged(self, value):
        self.__plugged = value
        
    @property
    def enabled(self):
        return self.__enabled

    @enabled.setter
    def enabled(self, value):
        self.__enabled = value

    @property
    def device(self):
        return self.__device

    @property
    def host(self):
        return self.__host

    @property
    def network(self):
        return self.__network


class Pool(XenAPIObjectMock):
    """Pool data structure for XenAPI Pool mock"""

    def __init__(self, hosts, networks):
        super(Pool, self).__init__()
        self.__hosts = [Host(networks) for i in xrange(hosts)]

    @property
    def hosts(self):
        return self.__hosts


class Host(XenAPIObjectMock):
    """Host data structure for XenAPI Host mock"""

    def __init__(self, networks):
        super(Host, self).__init__()
        self.__metrics = HostMetrics()
        self.__pifs = [PIF(self, networks[i], i * 2) for i in xrange(len(networks))] + \
                [PIF(self, networks[i], i * 2 + 1) for i in xrange(len(networks))]
        for pif in self.__pifs:
            pif.network.addPIF(pif)
        self.__enabled = True
        self.__vms = [VM(self, True)] # Control Domain

    @property
    def enabled(self):
        return self.__enabled

    @enabled.setter
    def enabled(self, value):
        self.__enabled = value

    @property
    def metrics(self):
        return self.__metrics

    @property
    def PIFs(self):
        return self.__pifs

    @property
    def VMs(self):
        return self.__vms

    @property
    def name(self):
        return "AFakeHostName"

    def startVMs(self, n=1):
        self.__vms = self.__vms + [VM()] * n

    def killAllVMs(self):
        self.__vms = self.__vms[:1]


class HostMetrics(XenAPIObjectMock):
    """Host metric data structure for XenAPI Hose Metrics mock"""

    def __init__(self):
        super(HostMetrics, self).__init__()
        self.__live = True

    @property
    def live(self):
        return self.__live

    @live.setter
    def live(self, liveness):
        self.__live = liveness


class VM(XenAPIObjectMock):
    """VM data structure for XenAPI VM mock"""

    def __init__(self, host, isdom0=False):
        super(VM, self).__init__()
        self.__host = host
        self.__controlDomain = isdom0

    @property
    def record(self):
        return {'is_control_domain': self.__controlDomain, \
                'resident_on': self.__host.opaque}

    @property
    def isControlDomain(self):
        return self.__controlDomain

    @property
    def host(self):
        return self.__host


class XenapiMock(mock.Mock):
    """
    session.xenapi lib mock class.

    As all lib are referred from session.xenapi, this needs to be mocked.
    This only replicate all required xenapi component as properties.
    """ 

    @property
    def pool(self):
        return XenapiPoolMock()

    @property
    def host(self):
        return XenapiHostMock()

    @property
    def host_metrics(self):
        return XenapiHostMetricsMock()

    @property
    def PIF(self):
        return XenapiPIFMock()

    @property
    def network(self):
        return XenapiPoolMock()

    @property
    def bond(self):
        return XenapiBondMock()

    @property
    def VM(self):
        return XenapiVMMock()


class XenapiNetworkMock(mock.Mock):
    """
    session.xenapi.network lib mock class.

    All network XenAPI calls are made on this module.
    """

    pass


class XenapiBondMock(mock.Mock):
    """
    session.xenapi.bond lib mock class.

    All bond XenAPI calls are made on this module.
    """

    pass


class XenapiPIFMock(mock.Mock):
    """
    session.xenapi.pif lib mock class.

    All pif XenAPI calls are made on this module.
    """

    def get_all(self):
        return [pif.opaque for host in Session.instance().hosts for pif in host.PIFs]

    def __getPIF(self, opaque):
        for p in [pif for host in Session.instance().hosts for pif in host.PIFs]:
            if p.opaque == opaque:
                return p

        raise Exception('Cannot find PIF opaque: %s' % opaque)

    def get_device(self, opaque):
        return self.__getPIF(opaque).device
        

class XenapiPoolMock(mock.Mock):
    """
    session.xenapi.pool lib mock class.

    All pool XenAPI calls are made on this module.
    """

    def get_all(self):
        return [pool.opaque for pool in Session.instance().pools]

    def __getPool(self, opaque):
        for p in Session.instance().pools:
            if p.opaque == opaque:
                return p

        raise Exception('Cannot find pool opaque: %s' % opaque)
                
    def get_master(self, opaque):
        return self.__getPool(opaque).hosts[0].opaque


class XenapiHostMock(mock.Mock):
    """
    session.xenapi.host lib mock class.

    All host XenAPI calls are made on this module.
    """

    def get_all(self):
        return [host.opaque for host in Session.instance().hosts]

    def __getHost(self, opaque):
        for h in Session.instance().hosts:
            if h.opaque == opaque:
                return h

        raise Exception('Cannot find host opaque: %s' % opaque)

    def get_record(self, opaque):
        host = self.__getHost(opaque)
        host_record = {'enabled': host.enabled, 'metrics': host.metrics.opaque}

        return host_record

    def get_hostname(self, opaque):
        return self.__getHost(opaque).name

    def get_uuid(self, opaque):
        return self.__getHost(opaque).uuid

    def get_PIFs(self, opaque):
        return [pif.opaque for pif in self.__getHost(opaque).PIFs]

    def get_management_interface(self, opaque):
        return self.__getHost(opaque).PIFs[0].opaque

    def call_plugin(self, *arg):
        return ""


class XenapiHostMetricsMock(mock.Mock):
    """
    session.xenapi.host_metrics lib mock class.
    """

    def __getMetrics(self, opaque):
        for h in Session.instance().hosts:
            if h.metrics.opaque == opaque:
                return h.metrics

        raise Exception('Cannot find host metrics opaque: %s' % opaque)

    def get_live(self, opaque):
        metrics = self.__getMetrics(opaque)
        return metrics.live


class XenapiVMMock(mock.Mock):
    """
    session.xenapi.vm lib mock class.
    """

    def __getVM(self, opaque):
        for h in Session.instance().hosts:
            for vm in h.VMs:
                if vm.opaque == opaque:
                    return vm

        raise Exception('Cannot find VM opaque: %s' % opaque)

    def get_is_control_domain(self, opaque):
        return self.__getVM(opaque).isControlDomain

    def get_resident_on(self, opaque):
        return self.__getVM(opaque).host.opaque

    def get_all_records(self):
        rec = {}
        for h in Session.instance().hosts:
            for vm in h.VMs:
                rec[vm.opaque] = vm.record

        return rec

