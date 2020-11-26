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

	def filter(self, grep, blacklist):
		'Apply grep and blacklist filter'
		grepper = Grep(grep)	# grep for address, link or no filter
		blacklist = BlackList(blacklist)	# filter out blacklisted addresses
		self.data = blacklist.filter(self.addresses, grepper.grep(self.data))

	def addgeo(self, extension='_geo'):
		'Add geo infos'
		geo_db = GeoLite2()
		for line in self.data:
			for addr in stats.addresses:
				line[addr + extension ] = geo_db.get_string(line[addr])

	def limit_data(self, maxdata):
		'Limit number of data sets'
		if maxdata != None and maxdata < len(self.data):
			self.data = self.data[:maxdata]

	def limit_nodes(self, maxnodes):
		'Linit number of nodes'
		if maxnodes != None and maxnodes < len(self.nodes):
			self.nodes = self.nodes[:maxnodes]
			self.node_addresses = { node['id'] for node in self.nodes }
