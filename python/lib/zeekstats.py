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
		self.bytes = 'orig_bytes', 'resp_bytes'
		if grep == None:
			self.columns = 'id.orig_h', 'id.resp_h', 'ts', 'orig_bytes', 'resp_bytes'
			self.type = 'basic'
		else:
			self.columns = 'id.orig_h', 'id.resp_h', 'id.resp_p', 'ts', 'orig_bytes', 'resp_bytes'
			self.type = 'grep'
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
		self.addgeo()

	def gen_nodes(self, maxnodes=None):
		'Generate nodes to display'
		self.addresses = { line['id.orig_h'] for line in self.data }	# all ip adressses, orig and resp
		self.addresses.update({ line['id.resp_h'] for line in self.data })
		self.nodes = []
		for addr in self.addresses:	#	generate list of nodes
			node = {'addr': addr.compressed}
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
		self.limit_nodes(maxnodes)
		self.addgeo2nodes()
		self.addresses = set()
		for node in self.nodes:
			self.addresses.add(node['addr'])
			node['value'] = node['total_bytes']
			node['title'] = {
				'first_ts': node['first_ts'],
				'last_ts': node['last_ts'],
				'total_bytes': node['total_bytes']
			}
			yield node

	def gen_edges(self):
		'Generate edges to display'
		id_cnt = 0	# for simple edge ids
		for line in self.data:
			edge = {'from': line['id.orig_h'].compressed, 'to': line['id.resp_h'].compressed}
			if not edge['from'] in self.addresses or not edge['to'] in self.addresses:
				continue
			id_cnt += 1
			edge['id'] = id_cnt
			edge['value'] = line['total_bytes']
			edge['arrows'] = 'to'
			edge['title'] = {
				'first_ts': line['first_ts'],
				'last_ts': line['last_ts'],
				'orig_bytes': line['orig_bytes'],
				'resp_bytes': line['resp_bytes'],
				'total_bytes': line['total_bytes']
			}
			yield edge


#			if self.type == 'grep':
#				edge['title'] = f'id.resp_p: {line["id.resp_p"]}',
#			self.edges.append(edge)			




