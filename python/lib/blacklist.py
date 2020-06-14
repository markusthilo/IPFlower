#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from lib.addresslist import AddressList

class BlackList(AddressList):
	'Load blacklist from file - one IP address per line'

	def match(self, addresses):
		'Check if at least one of the given addresses is in blacklist'
		for addr in addresses:
			if addr in self.addresses:
				return True
		return False

	def filter(self, keys, data):
		'Filter out blacklisted addresses from a list'
		if self.addresses == []:
			return data
		return [ dataset for dataset in data if not self.match(dataset[key] for key in keys) ]
