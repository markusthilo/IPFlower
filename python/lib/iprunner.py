#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from lib.basicstats import BasicStats
from lib.basicinout import CSVReader
from lib.blacklist import BlackList
from lib.grep import Grep
from ipaddress import ip_address

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
		'Use iprunner to calculate statistics'
		self.readcsv(infiles)
		self.datatype = self.__type__(self.columns)
		if self.datatype == 'shorter':
			self.addresses = 'ADDR'
		else:
			self.addresses = 'SRC_ADDR', 'DST_ADDR'
		self.timestamps = 'FIRST_TS', 'LAST_TS'
		self.grep(grep)
		self.blacklist(blacklist)
		self.addgeo(extension='_GEO')

	def __type__(self, columns):
		'Detect data type'
		for datatype, coldefs in self.TYPES:
			if columns == coldefs:
				return datatype
		raise RuntimeError('Unexpected input file.')

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
		if self.datatype == 's':
			self.edges = [
				{
					'from': line['ADDR'].compressed,
					'to': line['unknown'].compressed,
					'value': line['VOLUME']
				} for line in self.data]
		else:
			self.edges = [
				{
					'from': line['SRC_ADDR'].compressed,
					'to': line['DST_ADDR'].compressed,
					'value': line['VOLUME'],
					'SRC_ADDR': line['SRC_ADDR'],
					'SRC_PORT': line["SRC_PORT"],
					'DST_ADDR': line['DST_ADDR'],
					'DST_PORT': line["DST_PORT"],
					'PROTOCOL': line["PROTOCOL"],
					'FIRST_TS': line['FIRST_TS'],
					'LAST_TS': line['LAST_TS'],
					'PACKETS': line['PACKETS'],
					'VOLUME': line['VOLUME']
				} for line in self.data]




		self.stats.gen_nodes()
		self.stats.limit_nodes(maxout)
		if maxout != None and maxout < len(self.stats.nodes):
			self.stats.nodes = self.stats.nodes[:maxout]
		ids = set()
		for node in self.stats.nodes:
			ids.add(node['id'])
			geo = self.geo_db.get(node['id'])
			cc = geo['cc'].lower()
			geo_str = self.geo_db.gen_string(geo)
			self.html += '''
				nodes.push({'''
			self.html += f'id: "{node["id"]}", label: "{node["id"]}", shape: "image", image: DIR + "{cc}.svg"'
			try:
				self.html += f', value: {node[self.stats.total]}'
			except AttributeError:
				pass
			self.html += f''',
					title: "<table><tr><td colspan='3'>{node["id"]}</td></tr><tr><td colspan='3'>{geo_str}</td></tr>'''
			for row in self.nodeinfos:
				value = self.humanreadable(row, value)
				self.html += f'<tr><td>{row}</td><td> : </td><td>{value}</td></tr>'
			self.html += '</table>"});'
		self.stats.gen_edges()
		id_cnt = 0	# for simple edge ids
		for edge in self.stats.edges:
			if edge['from'] in ids and edge['to'] in ids:
				id_cnt += 1
				self.html += '''
				edges.push({'''
				self.html += f'id: "{id_cnt}"'
				self.html += f', from: "{edge["from"]}", to: "{edge["to"]}", value: {edge["value"]}'
				edge.pop('from')
				edge.pop('to')
				edge.pop('value')
				if len(edge) > 0:
					self.html += f''',
						title: "<table>'''
					for row, value in edge.items():
						value = self.humanreadable(row, value)
						self.html += f'<tr><td>{row}</td><td>:</td><td>{value}</td></tr>'
					self.html += '</table>"'
				try:
					if self.stats.arrows:
						self.html += ', arrows: "to"'
				except AttributeError:
					pass
				self.html += '});'
