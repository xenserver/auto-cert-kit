# /usr/bin/env python3

import subprocess


def make_local_call(call):
    """Function wrapper for making a simple call to shell"""
    process = subprocess.Popen(call, stdout=subprocess.PIPE, universal_newlines=True)    # NOSONAR
    stdout, stderr = process.communicate()
    if process.returncode == 0:
        return stdout.strip()
    else:
        raise Exception("Error: '%s' '%s'" % (stdout, stderr))
