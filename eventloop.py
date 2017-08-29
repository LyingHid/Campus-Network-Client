#!/usr/bin/python
# -*- coding: utf-8 -*-

import selectors

class Eventloop():
    def __init__(self):
        self.selector = selectors.DefaultSelector()
        self.files = {}


    def register(self, category, target):
        pass


    def modify(self, category, target):
        pass


    def unregister(self, category, target):
        pass
