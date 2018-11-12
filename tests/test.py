#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import unittest
import json

from pyintel471 import PyIntel471
from .keys import email, authkey


class TestBasic(unittest.TestCase):

    def setUp(self):
        self.intel = PyIntel471(email, authkey)

    def test_search(self):
        f = self.intel.detailled_filters(malwareFamily='lokibot')
        r = self.intel.search(f)
        print(json.dumps(r.json(), indent=2))
