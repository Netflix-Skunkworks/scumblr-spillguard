import os
import tempfile
import ipaddress
from contextlib import contextmanager

from scumblr_spillguard import log
from scumblr_spillguard.exceptions import AuthorizationError


def validate_ip(source_ip, whitelist):
    """Determine if we are getting a request from a whitelisted ip."""
    log.debug("Validating source IP")
    for cidr in whitelist:
        if ipaddress.IPv4Address(source_ip) in ipaddress.IPv4Network(cidr):
            log.debug("{} is in {}".format(source_ip, cidr))
            return True
        else:
            log.debug("{} is NOT in {}".format(source_ip, cidr))

    raise AuthorizationError()


@contextmanager
def mktempfile():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        name = f.name
    try:
        yield name
    finally:
        try:
            os.unlink(name)
        except OSError as e:
            log.debug("No file {0}".format(name))



