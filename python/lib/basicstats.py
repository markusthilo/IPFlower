#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Basic statistics

from lib.addresslist import AddressList
from datetime import datetime
from operator import itemgetter

class BasicStats:
	'Base for statistics'

	def exclude(self, raw, blacklist):
		'Filter out blacklisted addresses'
		if blacklist == None or blacklist == []:	# no blacklist?
			return raw
		ex = AddressList(blacklist)
		return [	# filter
			dataset for dataset in raw
			if not dataset[self.addresses[0]] in ex.addresses
			and not dataset[self.addresses[1]] in ex.addresses
		]

	def update(self, key, line):
		'Check and update timestamps and weights'
		if key in self.data:
			if line[self.timestamp] < self.data[key][self.timestamps[0]]:
				self.data[key][self.timestamps[0]] = line[self.timestamp]
			elif line[self.timestamp] > self.data[key][self.timestamps[1]]:
				self.data[key][self.timestamps[1]] = line[self.timestamp]
			for weight in self.weights:
				self.data[key][weight] += line[weight]
			return False
		self.data[key] = { addr: line[addr] for addr in self.addresses }
		if self.differential != None:
			self.data[key].update({self.differential: line[self.differential]})
		self.data[key].update({ ts: line[self.timestamp] for ts in self.timestamps })
		self.data[key].update({ weight: line[weight] for weight in self.weights })

	def firstandlast(self, target_addr):
		'Get first and last timestamp to a given IP address'
		first = None
		last = None
		for dataset in self.data:
			for addr in self.addresses:
				if dataset[addr] == target_addr:
					if first == None or dataset[self.timestamps[0]] < first:
						first = dataset[self.timestamps[0]]
					if last == None or dataset[self.timestamps[1]] > last:
						last = dataset[self.timestamps[1]]
		if first == None:
			return dict()
		return {'first_seen': first, 'last_seen': last}

	def humantime(self, ts):
		'Create full readable timestamp as string'
		return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f')

	def humanfirstandlast(self, target_addr):
		'Get first and last timestamp to a given IP address (as human readable string)'
		firstandlast = self.firstandlast(target_addr)
		return { ts: self.humantime(firstandlast[ts]) for ts in firstandlast }

	def limitdata(self, maxdata):
		'Limit number of data sets'
		if maxdata != None and maxdata < len(self.data):
			self.data = self.data[:maxdata]

	def limitnodes(self, maxnodes):
		'Linit number of nodes'
		if maxnodes != None and maxnodes < len(self.nodes):
			self.nodes = self.nodes[:maxnodes]
			self.node_addresses = { node['id'] for node in self.nodes }
