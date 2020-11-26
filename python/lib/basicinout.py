#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from lib.geolite2 import GeoLite2
from datetime import datetime
from csv import reader, writer
from ipaddress import ip_address

class BasicOutput:
	'Base for output classes'

	def humantime(self, ts):
		'Create full readable timestamp as string'
		return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f')

	def humanbytes(self, value):
		'Create full readable bytes'
		index = 0
		while value >= 10000:
			value /= 1000
			index += 1
		return f'{value} {("B", "KB", "MB", "GB", "TB", "PB")[index]}'

	def humanreadable(self, key, value):
		'Create full readable timestamp as string if key is in timestamps'
		if key in self.stats.timestamps:
			return self.humantime(value)
		elif key in self.stats.bytes:
			return self.humanbytes(value)
		else:
			return value

class CSVGenerator(BasicOutput):
	'Generator for tabstop-separated values'

	def __init__(self, stats,
		colnames = False,
		dialect = 'excel',
		delimiter = '\t',
		maxout = None,
		reverse = False,
		unixtime = False):
		'Generate object - colnames=True gives a headline, maxout=INTEGER limits output'
#		print(stats.data)
		geo_db = GeoLite2()
		stats.limit_data(maxout)
		if reverse:
			stats.data.reverse()
		self.data = []
		if not unixtime:
			for line in stats.data:
				for ts in stats.timestamps:
					line[ts] = self.humantime(line[ts])

			self.data.append(line)
			
			if not unixtime:
				for ts in self.timestamps:
					line[ts] = self.humantime(line[ts])
		self.colnames = colnames
		if self.colnames:
			if self.data == []:
				self.headline = 'No data.'
				return
			else:
				self.headline = '\t'.join(map(lambda tab: str(tab), self.data[0].keys()))

	def write(self, outfile):
		'Write to file or stdout'
		for line in self.genlines():
			print(line, file=out)

class CSVReader:
	'Read CSV files'

	def readcsv(self, infiles, delimiter='\t', dialect = 'excel', columns=None):
		'Read data from CSV file'
		self.data = []
		self.columns = None
		for infile in infiles:
			csvreader = reader(infile, delimiter=delimiter, dialect = dialect)
			csvlist = [ line for line in csvreader ]
			if columns == None:
				if self.columns == None:
					self.columns = csvlist[0]
				elif self.columns != csvlist[0]:
					raise RuntimeError('Inconsistent input files.')
				for line in csvlist[1:]:
					print(line, self.__genline__(self.columns, line))
					self.data.append(self.__genline__(self.columns, line))
			else:
				for line in csvlist:
					self.data.append(self.__genline__(columns, line))
		if columns != None:
			self.columns = columns

	def __decode__(self, string):
		'Decode string'
		for form in int, float, ip_address:
			try:
				return form(string) 
			except ValueError:
				pass
		return string

	def __genline__(self, columns, values):
		'Generate dict from one line'
		
		for col, value in zip(columns, values):
			print(col, value, type(value))
		
		
		
		return { col: self.__decode__(value) for col, value in zip(columns, values) }

