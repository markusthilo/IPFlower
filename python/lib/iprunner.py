#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from lib.basicstats import BasicStats
from lib.blacklist import BlackList
from lib.grep import Grep
from ipaddress import ip_address

class IPRunner(BasicStats):
	'Visualize netflow data'

	COLUMNS = {
		'g': ('SRC_ADDR', 'SRC_PORT', 'DST_ADDR', 'DST_PORT', 'PROTOCOL', 'FIRST_TS', 'LAST_TS', 'PACKETS', 'VOLUME'),
		's': ('ADDR', 'FIRST_TS', 'LAST_TS', 'PACKETS_IN', 'PACKETS_OUT', 'VOLUME_IN', 'VOLUME_OUT'),
		'n': ('SRC_ADDR', 'DST_ADDR', 'PROTOCOL', 'FIRST_TS', 'LAST_TS', 'PACKETS', 'VOLUME')
	}

	def __init__(self, infiles, grep=None, blacklist=None):
		'Use iprunner to calculate statistics'
		self.grep = grep
		self.addresses = 'SRC_ADDR', 'DST_ADDR'
		self.timestamps = 'FIRST_TS', 'LAST_TS'
		array = self.readtsv(infiles)
		if len(array[0]) == 9:
			self.datatype = 'g'
		elif len(array[0]) == 7:
			if isinstance(array[0][1], float):
				self.datatype = 's'
			else:
				self.datatype = 'n'
		self.gendict(array, self.COLUMNS[self.datatype])
		self.filter(grep, blacklist)

	def gen_nodes(self, maxnodes=None):
		'Generate nodes to display'
		self.nodes = []
		self.node_addresses = { line['SRC_ADDR'] for line in self.data }	# all ip adressses, orig and resp
		self.node_addresses.update({ line['DST_ADDR'] for line in self.data })
		for addr in self.node_addresses:
			node = {'id': addr.compressed}
			first_ts = None
			last_ts = None
			volume = 0
			for line in self.data:
				if addr == line['SRC_ADDR'] or addr == line ['DST_ADDR']:	# node is orig or resp
					if first_ts == None or line['FIRST_TS'] < first_ts:	# update timestamps
						first_ts = line['FIRST_TS']
					if last_ts == None or line['LAST_TS'] > last_ts:
						last_ts = line['LAST_TS']
					volume += line['VOLUME']
			node.update({'FIRST_TS': first_ts, 'LAST_TS': last_ts, 'VOLUME': volume})
			self.nodes.append(node)

	def gen_edges(self):
		'Generate edges to display'
		self.arrows = True
		if self.grep == None:
			self.edges = [
				{
					'from': line['SRC_ADDR'].compressed,
					'to': line['DST_ADDR'].compressed,
					'value': line['VOLUME']
				}
				for line in self.data
			]
		else:
			self.edges = [
				{
					'from': line['id.orig_h'].compressed,
					'to': line['id.resp_h'].compressed,
					'label': str(line['id.resp_p']),
					'value': line['total_bytes'],
				}
				for line in self.data
			]
