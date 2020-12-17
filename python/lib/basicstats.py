#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from lib.basicinout import CSVReader
from lib.grep import Grep
from lib.blacklist import BlackList
from ipaddress import ip_address
from lib.geolite2 import GeoLite2

class BasicStats:
	'Base for statistics'

	def str2zero(self, value):
		'Normalize - or another string to integer 0'
		if isinstance(value, str):
			return 0
		return value

	def blacklist(self, blacklist):
		'Blacklist filter'
		if blacklist != None:
			bl = BlackList(blacklist)
			self.data = bl.filter(self.addresses, grepper.grep(self.data))

	def grep(self, arg):
		'Grep fiter'
		grepper = Grep(arg)
		if len(grepper.addresses) > len(self.addresses):
			raise RuntimeError('Too many IP addresses to filter for.')
		self.data = grepper.grep(self.data)

	def limit_data(self, maxdata):
		'Limit number of data sets'
		if maxdata != None and maxdata < len(self.data):
			self.data = self.data[:maxdata]

	def limit_nodes(self, maxnodes):
		'Linit number of nodes'
		if maxnodes != None and maxnodes < len(self.nodes):
			self.nodes = self.nodes[:maxnodes]
