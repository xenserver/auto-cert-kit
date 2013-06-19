#/usr/bin/env python

import subprocess

def make_local_call(call):
    """Function wrapper for making a simple call to shell"""
    process = subprocess.Popen(call, stdout=subprocess.PIPE)
    stdout, stderr = process.communicate()
    if process.returncode == 0:
        return str(stdout).strip()
    else:
        raise Exception("Error: '%s' '%s'" % (stdout, stderr))

