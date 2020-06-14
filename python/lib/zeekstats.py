#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from lib.zeekcut import ZeekCut
from lib.basicstats import BasicStats
from lib.blacklist import BlackList
from ipaddress import ip_address
from operator import itemgetter

class CalcZeek(BasicStats):
	'Visualize netflow data'

	def __init__(self, infiles, target=None, blacklist=None):
		'Read data from Zeek logfiles and calculate statistics'
		self.timestamp = 'ts'
		self.timestamps = 'ts_1st', 'ts_last'
		self.addresses = 'id.orig_h', 'id.resp_h'
		self.weights = 'orig_bytes', 'resp_bytes'
		self.total = 'total_bytes'
		log = ZeekCut(infiles, columns=[	# use zeek-cut
			'ts',
			'id.orig_h', 'id.orig_p',
			'id.resp_h', 'id.resp_p',
			'orig_bytes', 'resp_bytes'
		])
		log.convert(force={
			'ts': float,
			'id.orig_h': ip_address, 'id.orig_p': int,
			'id.resp_h': ip_address,'id.resp_p': int,
			'orig_bytes': int, 'resp_bytes': int
		})
		
		blacklistfilter = BlackList(blacklist)	# filter out blacklisted addresses
		filtered = blacklistfilter.filter(self.addresses, log.data)
		self.data = dict()	# distionary to store the statistical data
		if target == None:	# go for all data flows
			self.target = None
			self.differential = None
			for line in filtered:
				self.update(line['id.orig_h'].compressed + '-' + line['id.resp_h'].compressed, line)
		else:
			if isinstance(target, str):
				self.target = ip_address(target)
			else:
				self.target = target
			self.differential = 'id.resp_p'
			for line in filtered:
				if line['id.resp_h'] == self.target:	# target is server, remote as client
					key = line['id.orig_h'].compressed + '->:' + str(line['id.orig_p'])
				elif line['id.orig_h'] == self.target:	# target is client, remote is server
					key = line['id.resp_h'].compressed + ':' + str(line['id.resp_p'])
				else:
					continue
				self.update(key, line)
		self.data = list(self.data.values())
		for line in self.data:
			line['total_bytes'] = line['orig_bytes'] + line['resp_bytes']
		self.data.sort(key=itemgetter('total_bytes'), reverse=True)

	def gen_nodes(self, maxnodes=None):
		'Generate nodes to display'
		self.nodes = []
		self.node_addresses = { line['id.orig_h'] for line in self.data }	# all ip adressses, orig and resp
		self.node_addresses.update({ line['id.resp_h'] for line in self.data })
		for addr in self.node_addresses:
			node = {'id': addr.compressed}
			ts_1st = None
			ts_last = None
			total_bytes = 0
			for line in self.data:
				if addr == line['id.orig_h'] or addr == line ['id.resp_h']:	# node is orig or resp
					if ts_1st == None or line['ts_1st'] < ts_1st:	# update timestamps
						ts_1st = line['ts_1st']
					if ts_last == None or line['ts_last'] > ts_last:
						ts_last = line['ts_last']
					total_bytes += line['total_bytes']
			node.update({'ts_1st': ts_1st, 'ts_last': ts_last, 'total_bytes': total_bytes})
			self.nodes.append(node)
		self.nodes.sort(key=itemgetter('total_bytes'), reverse=True)

	def gen_edges(self):
		'Generate edges to display'
		self.arrows = True
		if self.target == None:
			self.edges = [
				{
					'from': line['id.orig_h'].compressed,
					'to': line['id.resp_h'].compressed,
					'value': line['total_bytes'],
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
			
