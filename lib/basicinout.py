#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from datetime import datetime
from csv import reader, writer
from ipaddress import ip_address
from lib.geolite2 import GeoLite2

class BasicOutput:
	'Base for output classes'

	def __init__(self, config):
		'Create Objekt by defining geo database'
		self.geolite2 = GeoLite2(config)
		self.config = config

	def humantime(self, ts):
		'Create full readable timestamp as string'
		return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f')

	def humanbytes(self, value):
		'Create full readable bytes'
		index = 0
		while value > 1000 and index < 5:
			value /= 1000
			index += 1
		return f'{value} {("B", "KB", "MB", "GB", "TB", "PB")[index]}'

	def chng_humantime(self, line):
		'Change UNIX timestamps to human readable'
		for key in self.stats.timestamps:
			line[key] = self.humantime(line[key])
		return line

	def chng_humanbytes(self, line):
		'Change traffic volumes to human readable'
		for key in self.stats.bytes:
			line[key] = self.humanbytes(line[key])
		return line

	def geostring(self, geo):
		'Add geo locations'
		geostr = ''
		for val in geo.values():
			if val != '-':
				geostr += str(val) + ', '
		if geostr == '':
			geostr = '-'
		return geostr[:-2]

	def add_geostring(self, line):
		'Add geo locations'
		for key in self.stats.addresses:
			line[key + self.stats.geoextension] = self.geostring(self.geolite2.get(line[key]))
		return line

class CSVGenerator(BasicOutput):
	'Generator for tabstop-separated values'

	def __init__(self, outfile, stats, config,
		noheadline = False,
		dialect = 'excel',
		delimiter = '\t',
		maxout = None,
		reverse = False,
		unixtime = False,
		intbytes = False):
		super().__init__(config)
		self.stats = stats
		self.noheadline = noheadline
		self.reverse = reverse
		self.unixtime = unixtime
		self.intbytes = intbytes
		self.stats.limit_data(maxout)
		self.csvwriter = writer(outfile, dialect=dialect, delimiter=delimiter)

	def write(self):
		'Write to file or stdout'
		if len(self.stats.data) > 0:
			if not self.noheadline:
				self.csvwriter.writerow(self.stats.data[0].keys())
			if self.reverse:
				for line in reversed(self.stats.data):
					self.__writerow__(line)
			else:
				for line in self.stats.data:
					self.__writerow__(line)
		else:
			self.csvwriter.writerow(['No data'])

	def __writerow__(self, line):
		'Write one row to CSV file'
		if not self.unixtime:
			line = self.chng_humantime(line)
		if not self.intbytes:
			line = self.chng_humanbytes(line)
		line = self.add_geostring(line)
		self.csvwriter.writerow(line.values())

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
		return { col: self.__decode__(value) for col, value in zip(columns, values) }

