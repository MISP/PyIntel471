#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import unittest
import json
from datetime import datetime

from pyintel471 import PyIntel471
from .keys import email, authkey


class TestBasic(unittest.TestCase):

    def setUp(self):
        self.intel = PyIntel471(email, authkey)

    def test_search(self):
        f = self.intel.search_filters(malwareFamily='lokibot')
        p = self.intel.url_parameters(createdFrom=datetime(2018, 11, 11), createdUntil=datetime(2018, 11, 12))
        r = self.intel.search(filters=f, parameters=p)
        print(json.dumps(r.json(), indent=2))
