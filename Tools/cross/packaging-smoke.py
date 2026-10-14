"""Target-side smoke coverage for restored stdlib packages and pip."""

import distutils
import email.message
import encodings
import importlib
import json
import logging
import pip
import pkg_resources
import setuptools
import threading
import unittest
import wheel
import wsgiref.util
import xml.etree.ElementTree


assert json.loads('{"amiga": true}')["amiga"] is True
assert logging.getLogger("openamigapython").name == "openamigapython"
assert issubclass(unittest.TestCase, object)
assert email.message.Message is not None
assert importlib.import_module("math").sqrt(49) == 7
assert wsgiref.util.request_uri({
    "wsgi.url_scheme": "http",
    "SERVER_NAME": "amiga",
    "SERVER_PORT": "80",
    "SCRIPT_NAME": "",
    "PATH_INFO": "/python",
}) == "http://amiga/python"
assert xml.etree.ElementTree.fromstring("<amiga><python /></amiga>").tag == "amiga"
assert pip.__version__ == "20.3.4"
assert setuptools.__version__ == "44.1.1"
assert wheel.__version__ == "0.37.1"
assert pkg_resources is not None
lock = threading.RLock()
assert lock.acquire()
lock.release()

print "OPENAMIGAPYTHON-PACKAGING-SMOKE-OK"
print "pip", pip.__version__
print "setuptools", setuptools.__version__
print "wheel", wheel.__version__
