"""
Mock Values of XenServer Host for unittest
"""

CONFIG = {}
CONFIG["host"] = {}
CONFIG["expected"] = {}
CONFIG["host"]["ack_version"] = ["1.2.3"]
CONFIG["host"]["xs_software_version"] = [{'platform_name': 'XCP', 'product_version': '7.0.93', 'build_number': '133861c', 'xapi': '1.9', 'xen': '4.7.1-1-d', 'hostname': '0222bde6733f', 'network_backend': 'bridge', 'platform_version': '2.1.4',
                                          'product_version_text_short': '7.0', 'product_brand': 'XenServer', 'xencenter_max': '2.6', 'linux': '4.4.0+2', 'date': '2016-12-22', 'product_version_text': '7.0', 'xencenter_min': '2.6', 'dbv': '2016.0520'}
                                         ]

with open("autocertkit/tests/rawdata/dmidecode.out") as f:
    CONFIG["host"]["dmidecode"] = [f.read()]

with open("autocertkit/tests/rawdata/get_system_info.expected") as f:
    CONFIG["expected"]["get_system_info"] = [eval(f.read())]
