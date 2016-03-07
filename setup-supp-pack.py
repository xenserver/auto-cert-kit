from xcp.supplementalpack import *
from optparse import OptionParser

parser = OptionParser()
parser.add_option('--pdn', dest="product_name")
parser.add_option('--pdv', dest="product_version")
parser.add_option('--pln', dest="platform_name")
parser.add_option('--plv', dest="platform_version")
parser.add_option('--bld', dest="build")
parser.add_option('--out', dest="outdir")
(options, args) = parser.parse_args()

xs = Requires(originator='xcp', name='main', test='ge',
               product=options.platform_name, version='1.0.99',
               build='50762p')

setup(originator='xs', name='xs-auto-cert-kit', product=options.platform_name, 
      version=options.platform_version, build=options.build, vendor='Citrix Systems, Inc.', 
      description="XenServer Auto Cert Kit", packages=args, requires=[xs],
      outdir=options.outdir, output=['iso'])
