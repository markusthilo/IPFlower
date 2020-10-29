#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from lib.zeekcut import ZeekCut
from lib.basicstats import BasicStats
from ipaddress import ip_address
from operator import itemgetter

class CalcZeek(BasicStats):
	'Visualize netflow data'

	def __init__(self, infiles, grep=None, blacklist=None):
		'Read data from Zeek logfiles and calculate statistics'
		self.addresses = 'id.orig_h', 'id.resp_h'
		self.timestamps = 'first_ts', 'last_ts'
		self.grep = grep
		if grep == None:
			self.columns = 'id.orig_h', 'id.resp_h', 'ts', 'orig_bytes', 'resp_bytes'
		else:
			self.columns = 'id.orig_h', 'id.resp_h', 'id.resp_p', 'ts', 'orig_bytes', 'resp_bytes'
		zeekcut = ZeekCut()
		zeekcut.run(infiles, columns=self.columns)	# use zeek-cut
		zeekcut.convert()	# convert strings to fitting types
		self.data = zeekcut.data
		self.filter(grep, blacklist)	# filter by grep argument and blacklist
		newdata = []
		for line in self.data:
			orig_bytes = self.str2zero(line['orig_bytes'])
			resp_bytes = self.str2zero(line['resp_bytes'])
			must_create = True
			for newline in newdata:
				if ( line['id.orig_h'] == newline['id.orig_h']
					and line['id.resp_h'] == newline['id.resp_h'] ):
					if grep != None and line['id.resp_p'] != newline['id.resp_p']:
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
				if grep != None:
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
		self.node_addresses = { line['id.orig_h'] for line in self.data }	# all ip adressses, orig and resp
		self.node_addresses.update({ line['id.resp_h'] for line in self.data })
		for addr in self.node_addresses:
			node = {'id': addr.compressed}
			first_ts = None
			last_ts = None
			total_bytes = 0
			for line in self.data:
				if addr == line['id.orig_h'] or addr == line ['id.resp_h']:	# node is orig or resp
					if first_ts == None or line['first_ts'] < first_ts:	# update timestamps
						first_ts = line['first_ts']
					if last_ts == None or line['last_ts'] > last_ts:
						last_ts = line['last_ts']
					total_bytes += line['total_bytes']
			node.update({'first_ts': first_ts, 'last_ts': last_ts, 'total_bytes': total_bytes})
			self.nodes.append(node)
		self.nodes.sort(key=itemgetter('total_bytes'), reverse=True)

	def gen_edges(self):
		'Generate edges to display'
		self.arrows = True
		if self.grep == None:
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
			
