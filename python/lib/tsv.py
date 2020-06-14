#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from lib.basicoutput import BasicOutput
from lib.geolite2 import GeoLite2

class TSVGenerator(BasicOutput):
	'Generator for tabstop-separated values'

	def __init__(self, stats, colnames=False, maxout=None, reverse=False, unixtime=False):
		'Generate object - colnames=True gives a headline, maxout=INTEGER limits output'
		geo_db = GeoLite2()
		stats.limit_data(maxout)
		if reverse:
			stats.data.reverse()
		self.data = []
		for line in stats.data:
			if not unixtime:
				for ts in stats.timestamps:
					line[ts] = self.humantime(line[ts])
			for addr in stats.addresses:
				line[addr + '_geo' ] = geo_db.get_string(line[addr])
			self.data.append(line)
		self.colnames = colnames
		if self.colnames:
			if self.data == []:
				self.headline = 'No data.'
				return
			else:
				self.headline = '\t'.join(map(lambda tab: str(tab), self.data[0].keys()))

	def genlines(self):
		'Generate one string per line'
		if self.colnames:
			yield self.headline
		for line in self.data:
			yield '\t'.join(map(lambda tab: str(line[tab]), line))

	def write(self, out):
		'Write to file or stdout'
		for line in self.genlines():
			print(line, file=out)
