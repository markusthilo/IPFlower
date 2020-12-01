#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ipaddress import ip_address

class Grep():
	'Filter for IP address(es)'

	def __init__(self, arg):
		'Create filter'
		if arg == None or arg == '':
			self.addresses = []
			return
		self.addresses = [ ip_address(a) for a in arg.split('-') ]
		if len(self.addresses) > len:
			raise ValueError('Too many IP addresses to grep for.')

	def grep(self, data):
		'Generate filtered list'
		if len(self.addresses) == 1:
			return [ line for line in data if self.addresses[0] in line.values() ]
		elif len(self.addresses) == 2:
			return [ line for line in data
				if self.addresses[0] in line and self.addresses[1] in line.values() ]
		return data
