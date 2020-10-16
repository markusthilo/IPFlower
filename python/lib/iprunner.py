#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from lib.basicstats import BasicStats
from lib.blacklist import BlackList
from lib.grep import Grep
from ipaddress import ip_address
from operator import itemgetter

class CalcZeek(BasicStats):
	'Visualize netflow data'

	IPRUNNER = './iprunner'

	def __init__(self, infiles, grep=None, blacklist=None):
		'Use iprunner to calculate statistics'

		cmd = [self.IPRUNNER, '-c']	# assemble shell command for iprunner
		if grep != None:
			grepper = Grep(grep)
			cmd.append(grepper.argument())
		cmd.extend(infiles)
		iprunner = Popen(cmd, stdout=PIPE)	# generate zeek-cut
		lines = iprunner.communicate()[0].decode().rstrip('\n').split('\n')	# read lines from stdout
		self.columns = line[0].split('\t')
		data = [{colname: colvalue for colname, colvalue in zip(columns, line.split('\t'))} for line in lines[1:]]
		blacklistfilter = BlackList(blacklist)	# filter out blacklisted addresses
		data = blacklistfilter.filter(self.addresses, data)
		self.data = dict()	# distionary to store the statistical data


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
			
