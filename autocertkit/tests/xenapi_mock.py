"""
XenAPI Mock Lib for unittest

XenAPI requires a live session to XenServer hence needs to be mocked
while running unit tests.
"""

import mock
import random
import json
from XenAPI import XenAPI


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

        return ('Opaque: %sOpaque%s' % (clsname, suffix),
                '%sUUID%s' % (clsname, suffix))

    def __init__(self):
        self.__opaque, self.__uuid = self.__class__.genIdentity(
            self.__class__.__name__)

    @property
    def opaque(self):
        return self.__opaque

    @property
    def uuid(self):
        return self.__uuid


class Session(XenAPIObjectMock):
    """Session data structure for XenAPI Session mock"""

    __INSTANCE = {}
    __INITIALIZED = {}

    def __new__(cls, desc="Generic"):
        # There can be only 1 session during tests per desc.
        if desc not in Session.__INSTANCE:
            Session.__INSTANCE[desc] = super(Session, cls).__new__(cls)
            Session.__INITIALIZED[desc] = False
        return Session.__INSTANCE[desc]

    def __init__(self, desc="Generic"):
        if not self.__INITIALIZED[desc]:
            super(Session, self).__init__()
            self.fail_plugin = False

            if desc == "EmptySession":
                # Session is empty
                self.__initEmptySession()
            else:
                # Standard session - 2 hosts, 1 network
                self.__initGenericSession()

            if desc == "ACK is not installed on slave":
                self.hosts[1].setAckVersion(None)

            self.__INITIALIZED[desc] = True

    def __initEmptySession(self):
        self.__Pool = None
        self.__opaque = None
        self.__xenapi = None
        self.__networks = None

    def __initGenericSession(self, hosts=2, networks=1):
        self.__networks = [Network(i) for i in xrange(networks)]
        self.__pool = Pool(hosts, self.__networks)
        self.__xenapi = XenapiMock(self)

    @property
    def xenapi(self):
        return self.__xenapi

    @property
    def handle(self):
        return self.__opaque

    @property
    def pool(self):
        return self.__pool

    @property
    def hosts(self):
        return self.pool.hosts if self.pool else []

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
        return self.__plugged

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
        self.__metrics = HostMetrics(self)
        self.__pifs = [PIF(self, networks[i], i * 2) for i in xrange(len(networks))] + \
            [PIF(self, networks[i], i * 2 + 1) for i in xrange(len(networks))]
        for pif in self.__pifs:
            pif.network.addPIF(pif)
        self.__enabled = True
        self.__vms = [VM(self, True)]  # Control Domain
        self.__ack_version = "1.2.3"

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

    @property
    def ackVersion(self):
        return self.__ack_version

    def startVMs(self, n=1):
        self.__vms = self.__vms + [VM() for i in xrange(n)]

    def killAllVMs(self):
        self.__vms = self.__vms[1:]

    def setAckVersion(self, version):
        self.__ack_version = version


class HostMetrics(XenAPIObjectMock):
    """Host metric data structure for XenAPI Hose Metrics mock"""

    def __init__(self, host):
        super(HostMetrics, self).__init__()
        self.__host = host
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
        return {'is_control_domain': self.__controlDomain,
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

    def __init__(self, session):
        super(XenapiMock, self).__init__()
        self.__session = session
        self.__xenapiPool = XenapiPoolMock(self)
        self.__xenapiHost = XenapiHostMock(self)
        self.__xenapiHostMetrics = XenapiHostMetricsMock(self)
        self.__xenapiPif = XenapiPIFMock(self)
        self.__xenapiNetwork = XenapiNetworkMock(self)
        self.__xenapiBond = XenapiBondMock(self)
        self.__xenapiVm = XenapiVMMock(self)

    @property
    def session(self):
        return self.__session

    @property
    def pool(self):
        return self.__xenapiPool

    @property
    def host(self):
        return self.__xenapiHost

    @property
    def host_metrics(self):
        return self.__xenapiHostMetrics

    @property
    def PIF(self):
        return self.__xenapiPif

    @property
    def network(self):
        return self.__xenapiNetwork

    @property
    def bond(self):
        return self.__xenapiBond

    @property
    def VM(self):
        return self.__xenapiVm


class _XenapiSubclassMock(mock.Mock):

    def __init__(self, xenapi_ref):
        super(_XenapiSubclassMock, self).__init__()
        self.__xenapi = xenapi_ref

    @property
    def xenapi(self):
        return self.__xenapi

    @property
    def session(self):
        return self.xenapi.session


class XenapiNetworkMock(_XenapiSubclassMock):
    """
    session.xenapi.network lib mock class.

    All network XenAPI calls are made on this module.
    """

    pass


class XenapiBondMock(_XenapiSubclassMock):
    """
    session.xenapi.bond lib mock class.

    All bond XenAPI calls are made on this module.
    """

    pass


class XenapiPIFMock(_XenapiSubclassMock):
    """
    session.xenapi.pif lib mock class.

    All pif XenAPI calls are made on this module.
    """

    def get_all(self):
        return [pif.opaque for host in self.session.hosts for pif in host.PIFs]

    def __getPIF(self, opaque):
        for p in [pif for host in self.session.hosts for pif in host.PIFs]:
            if p.opaque == opaque:
                return p

        raise Exception('Cannot find PIF opaque: %s' % opaque)

    def get_device(self, opaque):
        return self.__getPIF(opaque).device

    def get_management(self, opaque):
        p = self.__getPIF(opaque)
        management = p.host.PIFs[0].opaque
        return opaque == management


class XenapiPoolMock(_XenapiSubclassMock):
    """
    session.xenapi.pool lib mock class.

    All pool XenAPI calls are made on this module.
    """

    def get_all(self):
        return [self.session.pool.opaque]

    def get_master(self, opaque):
        if self.session.pool.opaque != opaque:
            raise Exception('Cannot find pool opaque: %s' % opaque)
        return self.session.hosts[0].opaque


class XenapiHostMock(_XenapiSubclassMock):
    """
    session.xenapi.host lib mock class.

    All host XenAPI calls are made on this module.
    """

    def get_all(self):
        return [host.opaque for host in self.session.hosts]

    def __getHost(self, opaque):
        for h in self.session.hosts:
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

    def call_plugin(self, host_ref, plugin, method, *arg):
        if self.session.fail_plugin:
            m = mock.Mock(side_effect=XenAPI.Failure(
                "raised by Mock(): plugin failed"))
            m()

        if plugin == "autocertkit":
            obj = AckPluginMethods(self.session, host_ref)
            func = getattr(obj, method, None)
            if callable(func):
                return func(*arg)
            else:
                # autocertkit plugin has output in json format
                return json.dumps("")
        return ""

    def get_ack_version(self, opaque):
        return self.__getHost(opaque).ackVersion


class XenapiHostMetricsMock(_XenapiSubclassMock):
    """
    session.xenapi.host_metrics lib mock class.
    """

    def __getMetrics(self, opaque):
        for h in self.session.hosts:
            if h.metrics.opaque == opaque:
                return h.metrics

        raise Exception('Cannot find host metrics opaque: %s' % opaque)

    def get_live(self, opaque):
        metrics = self.__getMetrics(opaque)
        return metrics.live


class XenapiVMMock(_XenapiSubclassMock):
    """
    session.xenapi.vm lib mock class.
    """

    def __getVM(self, opaque):
        for h in self.session.hosts:
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
        for h in self.session.hosts:
            for vm in h.VMs:
                rec[vm.opaque] = vm.record

        return rec


class AckPluginMethods(object):

    def __init__(self, session, host_ref=None):
        self.__session = session
        self.__host_opaque = host_ref

    def get_ack_version(self, *arg):
        return json.dumps(self.__session.xenapi.host.get_ack_version(self.__host_opaque))
