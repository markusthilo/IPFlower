#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from lib.zeekcut import ZeekCut
from lib.basicstats import BasicStats
from operator import itemgetter

class Zeek(BasicStats):
	'Visualize netflow data'

<<<<<<< HEAD
	def __init__(self, infiles, config, grep=None, blacklist=None):
		'Read data from Zeek logfiles and calculate statistics'
		BasicStats.__init__(config)
=======
	def __init__(self, infiles, ports=False, grep=None, blacklist=None):
		'Read data from Zeek logfiles and calculate statistics'
		self.ports = ports
		self.vis_available = not ports
>>>>>>> c667a23a58649419aa394e887dfdf74f7c12f39c
		self.addresses = 'id.orig_h', 'id.resp_h'
		self.timestamps = 'first_ts', 'last_ts'
		self.bytes = 'orig_bytes', 'resp_bytes', 'total_bytes'
		if self.ports:
			self.columns = 'id.orig_h', 'id.resp_h', 'id.resp_p', 'ts', 'orig_bytes', 'resp_bytes'
		else:
			self.columns = 'id.orig_h', 'id.resp_h', 'ts', 'orig_bytes', 'resp_bytes'
		self.geoextension = '_geo'
		zeekcut = ZeekCut()
		zeekcut.run(infiles, columns=self.columns)	# use zeek-cut
		zeekcut.convert()	# convert strings to fitting types
		self.data = zeekcut.data
		self.grep(grep)	# filter data
		self.blacklist(blacklist)
		newdata = []
		for line in self.data:
			orig_bytes = self.str2zero(line['orig_bytes'])
			resp_bytes = self.str2zero(line['resp_bytes'])
			must_create = True
			for newline in newdata:
				if ( line['id.orig_h'] == newline['id.orig_h']
					and line['id.resp_h'] == newline['id.resp_h'] ):
					if self.ports and line['id.resp_p'] != newline['id.resp_p']:
						continue
					if line['ts'] < newline['first_ts']:	# update first seen
						newline['first_ts'] = line['ts']
					elif line['ts'] > newline['last_ts']:	# update last seen
						newline['last_ts'] = line['ts']
					newline['orig_bytes'] += orig_bytes
					newline['resp_bytes'] += resp_bytes
					must_create = False
					break
			if must_create:
				newline = {'id.orig_h': line['id.orig_h'], 'id.resp_h': line['id.resp_h']}
				if self.ports:
					newline['id.resp_p'] = line['id.resp_p']
				newline['first_ts'] = line['ts']
				newline['last_ts'] = line['ts']
				newline['orig_bytes'] = orig_bytes
				newline['resp_bytes'] = resp_bytes
				newdata.append(newline)
		self.data = newdata
		for line in self.data:
			line['total_bytes'] = line['orig_bytes'] + line['resp_bytes']
		self.data.sort(key=itemgetter('total_bytes'), reverse=True)

	def gen_nodes(self, maxnodes=None):
		'Generate nodes to display'
		self.nodes = []
		for addr in { line['id.orig_h'] for line in self.data } | { line['id.resp_h'] for line in self.data }:
			node = {'addr': addr.compressed}
			first_ts = None
			last_ts = None
			orig_bytes = 0
			resp_bytes = 0
			total_bytes = 0
			for line in self.data:
				if addr == line['id.orig_h'] or addr == line ['id.resp_h']:	# node is orig or resp
					if first_ts == None or line['first_ts'] < first_ts:	# update timestamps
						first_ts = line['first_ts']
					if last_ts == None or line['last_ts'] > last_ts:
						last_ts = line['last_ts']
					orig_bytes += line['orig_bytes']
					resp_bytes += line['resp_bytes']
					total_bytes += line['total_bytes']
			node.update({
				'first_ts': first_ts,
				'last_ts': last_ts,
				'orig_bytes': orig_bytes,
				'resp_bytes': resp_bytes,
				'total_bytes': total_bytes
			})
			self.nodes.append(node)
		self.nodes.sort(key=itemgetter('total_bytes'), reverse=True)
		self.limit_nodes(maxnodes)
		self.node_addresses = set()
		for node in self.nodes:
			self.node_addresses.add(node['addr'])
			node['value'] = node['total_bytes']
			node['title'] = {
				'first_ts': node['first_ts'],
				'last_ts': node['last_ts'],
				'orig_bytes': node['orig_bytes'],
				'resp_bytes': node['resp_bytes'],
				'total_bytes': node['total_bytes']
			}
			yield node

	def gen_edges(self):
		'Generate edges to display'
		id_cnt = 0	# for simple edge ids
		edges = []
		for line in self.data:
			edge = {'from': line['id.orig_h'].compressed, 'to': line['id.resp_h'].compressed}
			if not edge['from'] in self.node_addresses or not edge['to'] in self.node_addresses:
				continue
			if {edge['from'], edge['to']} in edges:
				continue
			id_cnt += 1
			edge['id'] = id_cnt
			yield edge
