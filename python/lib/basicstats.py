#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from operator import itemgetter

class BasicStats:
	'Base for statistics'

	def update(self, key, line):
		'Check and update timestamps and weights'
		if key in self.data:	# update
			if line[self.timestamp] < self.data[key][self.timestamps[0]]:	# update 1st seen
				self.data[key][self.timestamps[0]] = line[self.timestamp]
			elif line[self.timestamp] > self.data[key][self.timestamps[1]]:	# update last seen
				self.data[key][self.timestamps[1]] = line[self.timestamp]
			for weight in self.weights:	# update weigths = add
				self.data[key][weight] += line[weight]
			return
		self.data[key] = { addr: line[addr] for addr in self.addresses }	# generate data set
		if self.differential != None:	# if target is given, generate port
			self.data[key].update({self.differential: line[self.differential]})
		self.data[key].update({ ts: line[self.timestamp] for ts in self.timestamps })	# generate timestamps
		self.data[key].update({ weight: line[weight] for weight in self.weights })

	def limit_data(self, maxdata):
		'Limit number of data sets'
		if maxdata != None and maxdata < len(self.data):
			self.data = self.data[:maxdata]

	def limit_nodes(self, maxnodes):
		'Linit number of nodes'
		if maxnodes != None and maxnodes < len(self.nodes):
			self.nodes = self.nodes[:maxnodes]
			self.node_addresses = { node['id'] for node in self.nodes }
