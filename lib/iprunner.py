#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from lib.basicstats import BasicStats
from lib.basicinout import CSVReader
from operator import itemgetter

class IPRunner(BasicStats, CSVReader):
	'Visualize netflow data'

	TYPES = (
		('grep', [
			'SRC_ADDR',
			'SRC_PORT',
			'DST_ADDR',
			'DST_PORT',
			'PROTOCOL',
			'FIRST_TS',
			'LAST_TS',
			'PACKETS',
			'VOLUME'
		]),
		('shorter', [
			'ADDR',
			'FIRST_TS',
			'LAST_TS',
			'PACKETS_IN',
			'PACKETS_OUT',
			'VOLUME_IN',
			'VOLUME_OUT'
		]),
		('basic', [
			'SRC_ADDR',
			'DST_ADDR',
			'PROTOCOL',
			'FIRST_TS',
			'LAST_TS',
			'PACKETS',
			'VOLUME'
		])
	)


	def __init__(self, infiles, grep=None, blacklist=None):
		'Get statistics from TSV file generated by IPRUNNER'
		self.readcsv(infiles)
		self.datatype = self.__type__(self.columns)
		if self.datatype == 'basic':
			self.vis_available = True
		else:
			self.vis_available = False
		if self.datatype == 'shorter':
			self.addresses = ('ADDR',)
			self.bytes = 'VOLUME_IN', 'VOLUME_OUT'
		else:
			self.addresses = 'SRC_ADDR', 'DST_ADDR'
			self.bytes = ('VOLUME',)
		self.timestamps = 'FIRST_TS', 'LAST_TS'
		self.geoextension = '_GEO'
		self.grep(grep)
		self.blacklist(blacklist)

	def __type__(self, columns):
		'Detect data type'
		for datatype, coldefs in self.TYPES:
			if columns == coldefs:
				return datatype
		raise RuntimeError('Unexpected input file.')

	def gen_nodes(self, maxnodes=None):
		'Generate nodes to display'
		self.nodes = []
		for addr in { line['SRC_ADDR'] for line in self.data } | { line['DST_ADDR'] for line in self.data }:
			node = {'addr': addr.compressed}
			first_ts = None
			last_ts = None
			packets_in = 0
			packets_out = 0
			volume_in = 0
			volume_out = 0
			for line in self.data:
				if addr == line['SRC_ADDR'] or addr == line ['DST_ADDR']:	# node is src or dst
					if first_ts == None or line['FIRST_TS'] < first_ts:	# update timestamps
						first_ts = line['FIRST_TS']
					if last_ts == None or line['LAST_TS'] > last_ts:
						last_ts = line['LAST_TS']
					if addr == line['SRC_ADDR']:	# add up traffic
						packets_out += line['PACKETS']
						volume_out += line['VOLUME']
					else:
						packets_in += line['PACKETS']
						volume_in += line['VOLUME']
			node.update({
				'FIRST_TS': first_ts,
				'LAST_TS': last_ts,
				'PACKETS_IN': packets_in,
				'PACKETS_OUT': packets_out,
				'PACKETS_ALL': packets_in + packets_out,
				'VOLUME_IN': volume_in,
				'VOLUME_OUT': volume_out,
				'VOLUME_ALL': volume_in + packets_out,
			})
			self.nodes.append(node)
		self.nodes.sort(key=itemgetter('VOLUME_ALL'), reverse=True)
		self.limit_nodes(maxnodes)
		self.node_addresses = set()
		for node in self.nodes:
			self.node_addresses.add(node['addr'])
			node['value'] = node['VOLUME_ALL']
			node['title'] = {
				'FIRST_TS': node['FIRST_TS'],
				'LAST_TS': node['LAST_TS'],
				'PACKETS_IN': node['PACKETS_IN'],
				'PACKETS_OUT': node['PACKETS_OUT'],
				'PACKETS_ALL': node['PACKETS_ALL'],
				'VOLUME_IN': node['VOLUME_IN'],
				'VOLUME_OUT': node['VOLUME_OUT'],
				'VOLUME_ALL': node['VOLUME_ALL']
			}
			yield node

	def gen_edges(self):
		'Generate edges to display'
		id_cnt = 0	# for simple edge ids
		edges = []
		for line in self.data:
			edge = {'from': line['SRC_ADDR'].compressed, 'to': line['DST_ADDR'].compressed}
			if not edge['from'] in self.node_addresses or not edge['to'] in self.node_addresses:
				continue
			if {edge['from'], edge['to']} in edges:
				continue
			id_cnt += 1
			edge['id'] = id_cnt
			yield edge