#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from lib.grep import Grep
from lib.blacklist import BlackList
from ipaddress import ip_address

class BasicStats:
	'Base for statistics'

	def readtsv(self, infiles):
		'Read data from TSV file'
		return [[self.decode(value) for value in line.split('\t')] for infile in infiles for line in infile]

	def decode(self, string):
		'Decode string to fitting formats'
		string = string.strip('\n')
		string = string.strip('\t')
		for form in int, float, ip_address:
			try:
				return form(string)
			except ValueError:
				pass
		return string

	def gendict(self, array, columns):
		'Generate dictionary from list of lists'
		self.data = [{colname: colvalue for colname, colvalue in zip(columns, line)} for line in array]

	def str2zero(self, value):
		'Normalize - or another string to integer 0'
		if isinstance(value, str):
			return 0
		return value

	def filter(self, grep, blacklist):
		'Apply grep and blacklist filter'
		grepper = Grep(grep)	# grep for address, link or no filter
		blacklist = BlackList(blacklist)	# filter out blacklisted addresses
		self.data = blacklist.filter(self.addresses, grepper.grep(self.data))

	def limit_data(self, maxdata):
		'Limit number of data sets'
		if maxdata != None and maxdata < len(self.data):
			self.data = self.data[:maxdata]

	def limit_nodes(self, maxnodes):
		'Linit number of nodes'
		if maxnodes != None and maxnodes < len(self.nodes):
			self.nodes = self.nodes[:maxnodes]
			self.node_addresses = { node['id'] for node in self.nodes }
