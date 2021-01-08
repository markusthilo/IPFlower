#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Network visualisation

from lib.basicinout import BasicOutput

class NetVis(BasicOutput):
	'Generate html with JavaScript for network visualisation of the statistic netflow data'

	def __init__(self, stats, config, maxnodes=1000):
		'Base for isualisation using Vis.js'
		super().__init__(config)
		self.stats = stats
		if len(self.stats.data) == 0:
			self.html = '''<html>
	<body>
		<p>No data to display</p>
	</body>
</html>'''
			return
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
		<link href="./visjs/node_modules/vis-network/dist/dist/vis-network.min.css" rel="stylesheet" type="text/css" />
		<script type="text/javascript" src="./visjs/node_modules/vis-network/dist/vis-network.js"></script>
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
		for node in self.stats.gen_nodes(maxnodes):	# nodes for vis.js
			self.html += '''
				nodes.push({'''
			geoinfo = self.geolite2.get(node['addr'])
			cc = geoinfo['cc'].lower()
			geostr = self.geostring(geoinfo)
			self.html += f'id: "{node["addr"]}", label: "{node["addr"]}", shape: "image", image: DIR + "{cc}.svg"'
			try:
				self.html += f', value: {node["value"]}'
			except KeyError:
				pass
			self.html += f''',
					title: "<table><tr><td colspan='3'>{node["addr"]}</td></tr><tr><td colspan='3'>{geostr}</td></tr>'''
			try:
				self.html += self.titlerows(node['title'])
			except KeyError:
				pass
			self.html += '</table>"});'
		for edge in self.stats.gen_edges():	# edges for vis.js
			self.html += '''
				edges.push({'''
			self.html += f'id: "{edge["id"]}", from: "{edge["from"]}", to: "{edge["to"]}"'
			try:
				self.html += f', value: {edge["value"]}'
			except KeyError:
				pass
			try:
				self.html += f', arrows: "{edge["arrows"]}"'
			except KeyError:
				pass
			try:
				
				self.html += f''',
					title: "<table>{self.titlerows(edge['title'])}</table>"'''
			except KeyError:
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

	def titlerows(self, title):
		'Make bytes and timestamps readable'
		html = ''
		for key, value in title.items():
			if key in self.stats.bytes:
				value = self.humanbytes(value)
			elif key in self.stats.timestamps:
				value = self.humantime(value)
			html += f'<tr><td>{key}</td><td> : </td><td>{value}</td></tr>'
		return html

	def write(self, outfile):
		'Write html'
		print(self.html, file=outfile)
