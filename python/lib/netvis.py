#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Network visualisation

from lib.basicinout import BasicOutput
from lib.geolite2 import GeoLite2
from datetime import datetime

class NetVis(BasicOutput):
	'Generate HTML with JavaScript for network visualisation of the statistic netflow data'

	def __init__(self, stats, maxout=None):
		'Visualisation using Vis.js'
		self.geo_db = GeoLite2()
		self.stats = stats
		self.html = '''<html>
	<head>
		<meta charset="utf-8"><title>IPFlower</title>
		<link rel="icon" href="./pixmaps/icons/ipflower.ico">
		<style>
			body {font-family: Sans-Serif; font-size: 0.8em}
			p{font-family: sans-serif;} table{font-family: sans-serif}
			table {font-family: Sans-Serif; font-size: 1em}
			td {white-space: nowrap}
			input[type=text] {width: 100%; box-sizing: border-box}
		</style>
		<link href="./javascript/node_modules/vis-network/dist/dist/vis-network.min.css" rel="stylesheet" type="text/css" />
		<script type="text/javascript" src="./javascript/node_modules/vis-network/dist/vis-network.js"></script>
		<script type="text/javascript">
			var nodes = null;
			var edges = null;
			var network = null;
			var DIR = './pixmaps/flags/';
			var EDGE_LENGTH_MAIN = 150;
			var EDGE_LENGTH_SUB = 50;
			function draw() {
				nodes = [];
				edges = [];'''
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
			for row, value in node.items():
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
		self.html += '''
				var container = document.getElementById('netvis');
				var data = {
					nodes: nodes,
					edges: edges
				};
				var options = {
					"physics": {
						"enabled": false,
						"hierarchicalRepulsion": {
						"centralGravity": 0,
						"avoidOverlap": null
						}
					}
				};
				network = new vis.Network(container, data, options);
			}
		</script>
	</head>
	<body onload="draw()">
		<div id="netvis"></div>
	</body>
</html>'''

	def write(self, out):
		'Write to file or stdout'
		print(self.html, file=out)
