#!/usr/bin/env python

from distutils.core import setup

setup(name='AutoCertKit',
      version='@KIT_VERSION@',
      author='Citrix System Inc.',
      url='http://github.com/xenserver/auto-cert-kit',
      packages=['acktools', 'acktools.net'],
      )
