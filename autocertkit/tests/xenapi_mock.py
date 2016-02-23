"""
XenAPI Mock Lib for unittest

XenAPI requires a live session to XenServer hence needs to be mocked
while running unit tests.
"""
#!/usr/bin/python

import mock
import random

class XenAPIObject(object):
    """Base class for XenAPI object models"""

    USED_SUFFIXES = []

    @classmethod
    def genOpaque(cls, clsname=''):
        """A Opaque generator"""

        suffix = '_%d' % random.randint(0, 9999999)
        while suffix in cls.USED_SUFFIXES:
            suffix = '_%d' % random.randint(0, 9999999)
        cls.USED_SUFFIXES.append(suffix)

        return 'Opaque: %sOpaque%s' % (clsname, suffix)

    def __init__(self):
        self.__opaque = self.__class__.genOpaque(self.__class__.__name__)

    @property
    def opaque(self):
        return self.__opaque


class Session(XenAPIObject):
    """Session data structure for XenAPI Session mock"""

    __INSTANCE = None

    @classmethod
    def instance(cls):
        # session needs to be the same while test runs throughly.
        if Session.__INSTANCE is None:
            Session.__INSTANCE = Session()
        return Session.__INSTANCE

    def __init__(self):
        super(Session, self).__init__()
        self.__pool = Pool()
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


class Pool(XenAPIObject):
    """Pool data structure for XenAPI Pool mock"""

    def __init__(self):
        super(Pool, self).__init__()
        self.__hosts = [Host(), Host()]

    @property
    def hosts(self):
        return self.__hosts


class Host(XenAPIObject):
    """Host data structure for XenAPI Host mock"""

    def __init__(self):
        super(Host, self).__init__()
        self.__metrics = HostMetrics()
        self.__enabled = True

    @property
    def enabled(self):
        return self.__enabled

    @enabled.setter
    def enabled(self, value):
        if type(self.__enabled) != type(value):
            raise Exception('Type mismatched.')
        self.__enabled = value

    @property
    def metrics(self):
        return self.__metrics


class HostMetrics(XenAPIObject):
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


class XenapiMock(mock.Mock):
    """
    session.xenapi lib mock class.

    As all lib are referred from session.xenapi, this needs to be mocked.
    This only replicate all required xenapi component as properties.
    """

    @property
    def pool(self):
        return PoolMock()

    @property
    def host(self):
        return HostMock()

    @property
    def host_metrics(self):
        return HostMetricsMock()


class PoolMock(mock.Mock):
    """
    session.xenapi.pool lib mock class.

    All pool XenAPI calls are made on this module.
    """

    def get_all(self):
        # For ACK only 1 pool of 2 hosts exist only.
        return [pool.opaque for pool in Session.instance().pools]

    def __getPool(self, opaque):
        for p in Session.instance().pools:
            if p.opaque == opaque:
                return p

        raise Exception('Cannot find pool opaque: %s' % opaque)

    def get_master(self, opaque):
        return self.__getPool(opaque).hosts[0].opaque


class HostMock(mock.Mock):
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
        return "AHostNameMock"

    def get_uuid(self, opaque):
        return "AHostUUIDMock"


class HostMetricsMock(mock.Mock):
    """
    session.xenapi.host_metrics lib mock class.
    """

    def __init__(self):
        super(HostMetricsMock, self).__init__()
        self.__live = True

    def __getMetrics(self, opaque):
        for h in Session.instance().hosts:
            if h.metrics.opaque == opaque:
                return h.metrics

        raise Exception('Cannot find host metrics opaque: %s' % opaque)

    def get_live(self, opaque):
        metrics = self.__getMetrics(opaque)
        return metrics.live

