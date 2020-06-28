import random


def generate_mac():
    """
    This function will generate a random MAC.
    The function generates a MAC with the Xensource, Inc. OUI '00:16:3E'.
    Care should be taken to ensure duplicates are not used.   
    """
    mac = [0x00, 0x16, 0x3e,
           random.randint(0x00, 0x7f),  # NOSONAR
           random.randint(0x00, 0xff),  # NOSONAR
           random.randint(0x00, 0xff)]  # NOSONAR
    return ':'.join(map(lambda x: "%02x" % x, mac))
