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

"""Module for analysing test kit XML output in order to provide a useful overview to the caller."""

import textwrap
from xml.dom import minidom

from utils import *
from models import *

def count_by_result(class_recs, fn):
    """Return the list of tests which passed"""

    test_matches = []

    for class_name, (method_list, test_class_caps) in class_recs.iteritems():
        for method in method_list:
            if fn(method['result']):
                test_matches.append("%s.%s" % (class_name, method['test_name']))

    return test_matches

def wrap_text(string, width):
    return textwrap.wrap(string.strip(), width, subsequent_indent=' ' * 5)

def print_system_info(stream):
    """ Retrieve system information from SMBIOS and write to given stream. """
    sys_info = search_dmidecode("System Information")
    stream.write("#########################\n")
    stream.write("System Information from SMBIOS\n")
    stream.write('\n'.join(sys_info))
    stream.write("#########################\n")
    stream.write("\n")

def post_test_report(xml_file, output_file):
    devices = create_models(xml_file)
    
    all_passed = True
    fh = open(output_file, 'w')
    print_system_info(fh)
    for device in devices:
        device.print_report(fh)
        if not device.has_passed():
            all_passed = False
    fh.close()
    return all_passed
