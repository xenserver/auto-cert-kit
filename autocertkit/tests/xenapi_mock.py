"""
XenAPI Mock Lib for unittest

XenAPI requires a live session to XenServer hence needs to be mocked
while running unit tests.
"""

import mock
import random
import json
import XenAPI
from config import CONFIG


class XenObjectMock(object):
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


class Session(XenObjectMock):
    """Session data structure for XenAPI Session mock"""

    def __init__(self):
        super(Session, self).__init__()
        self.fail_plugin = False
        self.__initGenericSession()

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


class Network(XenObjectMock):
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


class PIF(XenObjectMock):
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

    @property
    def status(self):
        return "up" if self.plugged and self.enabled else "down"


class Pool(XenObjectMock):
    """Pool data structure for XenAPI Pool mock"""

    def __init__(self, hosts, networks):
        super(Pool, self).__init__()
        self.__hosts = [Host(networks) for i in xrange(hosts)]

    @property
    def hosts(self):
        return self.__hosts


class Host(XenObjectMock):
    """Host data structure for XenAPI Host mock"""

    def __init__(self, networks):
        super(Host, self).__init__()
        self.__metrics = HostMetrics()
        self.__pifs = [PIF(self, networks[i], i * 2) for i in xrange(len(networks))] + \
            [PIF(self, networks[i], i * 2 + 1) for i in xrange(len(networks))]
        for pif in self.__pifs:
            pif.network.addPIF(pif)
        self.__enabled = True
        self.__vms = [VM(self, True)]  # Control Domain
        self.__ack_version = CONFIG["host"]["ack_version"][0]
        self.xs_software_version = CONFIG["host"]["xs_software_version"][0]
        self.dmidecode = CONFIG["host"]["dmidecode"][0]
        self.__supportedPlugins = {"autocertkit": AckPluginMethods(self)}

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
        self.__vms = self.__vms + [VM(self) for i in xrange(n)]

    def killAllVMs(self):
        self.__vms = self.__vms[1:]

    def setAckVersion(self, version):
        self.__ack_version = version

    @property
    def supportedPlugins(self):
        return self.__supportedPlugins

    def addNewPlugin(self, name, plugin):
        self.__supportedPlugins.update({name: plugin})

    def removePlugin(self, name):
        del self.__supportedPlugins[name]


class HostMetrics(XenObjectMock):
    """Host metric data structure for XenAPI Host Metrics mock"""

    def __init__(self):
        super(HostMetrics, self).__init__()
        self.__live = True

    @property
    def live(self):
        return self.__live

    @live.setter
    def live(self, liveness):
        self.__live = liveness


class VM(XenObjectMock):
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


class XenapiMockBase(mock.Mock):

    def __init__(self, xenapi_ref):
        super(XenapiMockBase, self).__init__()
        self.__xenapi = xenapi_ref

    @property
    def xenapi(self):
        return self.__xenapi

    @property
    def session(self):
        return self.xenapi.session


class XenapiNetworkMock(XenapiMockBase):
    """
    session.xenapi.network lib mock class.

    All network XenAPI calls are made on this module.
    """

    pass


class XenapiBondMock(XenapiMockBase):
    """
    session.xenapi.bond lib mock class.

    All bond XenAPI calls are made on this module.
    """

    pass


class XenapiPIFMock(XenapiMockBase):
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


class XenapiPoolMock(XenapiMockBase):
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


class XenapiHostMock(XenapiMockBase):
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

    def get_software_version(self, opaque):
        return self.__getHost(opaque).xs_software_version

    def get_management_interface(self, opaque):
        return self.__getHost(opaque).PIFs[0].opaque

    def call_plugin(self, host_ref, plugin, method, *arg):
        if self.session.fail_plugin:
            m = mock.Mock(side_effect=XenAPI.Failure(
                "raised by Mock(): plugin failed"))
            m()

        h = self.__getHost(host_ref)
        if plugin in h.supportedPlugins:
            obj = h.supportedPlugins[plugin]
            func = getattr(obj, method, None)
            if callable(func):
                return func(*arg)
        return ""


class XenapiHostMetricsMock(XenapiMockBase):
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


class XenapiVMMock(XenapiMockBase):
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

    def __init__(self, host):
        self.__hostObj = host

    def __getattr__(self, name):
        return self.__defaultOutput

    def __defaultOutput(self, args):
        return json.dumps("")

    def get_ack_version(self, args):
        return json.dumps(self.__hostObj.ackVersion)

    def get_dmidecode_output(self, args):
        return json.dumps(self.__hostObj.dmidecode)

    def set_nic_device_status(self, args):
        print args
        pif = [p for p in self.__hostObj.PIFs if p.device == args['device']]
        pif[0].plugged = True if args['status'] == "up" else False

    def get_local_device_linkstate(self, args):
        pif = [p for p in self.__hostObj.PIFs if p.device == args['device']][0]
        out = {}
        out['link'] = "unknown" if not pif else (
            "yes" if pif.plugged else "no")
        out['operstate'] = "down" if not pif else pif.status
        out['carrier'] = "running" if out['operstate'] == "up" else ""
        return json.dumps(out)
