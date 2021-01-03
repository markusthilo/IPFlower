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
<<<<<<< HEAD

	def addgeo(self, extension='_geo'):
		'Add geo infos'
		geo_db = GeoLite2()
		for line in self.data:
			for addr in self.addresses:
				line[addr + extension ] = geo_db.get_string(line[addr])

	def addgeo2nodes(self):
		'Get country code in lower characters'
		geo_db = GeoLite2()
		for node in self.nodes:
			geo = geo_db.get(node['addr'])
			node['cc'] = geo['cc'].lower()
			node['geo'] = geo_db.gen_string(geo)
=======
>>>>>>> c667a23a58649419aa394e887dfdf74f7c12f39c
