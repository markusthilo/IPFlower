#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from datetime import datetime
from csv import reader, writer

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

	def __init__(self, infiles, delimiter='\t' ,columns=None, decoder=None):
		'Read data from TSV file'
		self.array = []
		self.columns = None
		for infile in infiles:
			csvreader = reader(infile, delimiter=delimiter)
			csvlist =[ line for line in csvreader ]

			print(csvlist)

			if columns == None:
				if self.columns == None:
					self.columns = csvlist[0]
				elif self.columns != csvlist[0]:
					raise RuntimeError('Inconsistent input files.')
					
			self.columns = self.__readline__[0][0]
			for infile in infiles:
				thiscols = self.__readline__(infile[0])

				for line in infile:
					self.array.append(self.__readline__(line, decoder=decoder))
		else:
			self.array = [self.readline(line, decoder=decoder) for line in infile]
		self.dict = [{colname: colvalue for colname, colvalue in zip(self.columns, line)} for line in array]

	def __readline__(self, line, decoder=None):
		'Read one line from file'
		if decoder == None:
			return [col for col in line.split('\t')]
		else:
			return [decoder(col) for col in line.split('\t')]
