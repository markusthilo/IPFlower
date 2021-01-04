#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ipaddress import ip_address

class AddressList:
	'Load IP addresses from a file - one address per line'

	def __init__(self, listfiles):
		'Load IPs into self.addresses'
		self.addresses = []
		if listfiles != None:	
			for listfile in listfiles:
				for line in listfile:
					try:
						self.addresses.append(ip_address(line.rstrip()))
					except ValueError:
						pass
