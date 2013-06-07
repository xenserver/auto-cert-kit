from xcp.supplementalpack import *
from optparse import OptionParser

parser = OptionParser()
parser.add_option('--pdn', dest="product_name")
parser.add_option('--pdv', dest="product_version")
parser.add_option('--bld', dest="build")
parser.add_option('--out', dest="outdir")
(options, args) = parser.parse_args()

xs = Requires(originator='xs', name='main', test='ge', 
               product=options.product_name, version='5.6.100', 
               build='39265p')

setup(originator='xs', name='xs-auto-cert-kit', product=options.product_name, 
      version=options.product_version, build=options.build, vendor='Citrix Systems, Inc.', 
      description="XenServer Auto Cert Kit", packages=args, requires=[xs],
      outdir=options.outdir, output=['iso'])
