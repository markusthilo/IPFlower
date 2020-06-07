#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Base tools to work with pcap files

from os import scandir, path
from subprocess import Popen

class Pcap:
	'Working with PCAP files'

	def __init__(self, filestruct):
		'PCAP files have to be stored in a directory pcap under the root directory'
		self.filestruct = filestruct

	def tree(self):
		'Give sorted directory tree on server filtered by pcap files'
		def __ls__(path, indent):
			'Recursion'
			file_cnt = 0	# in case list is empty
			for entry in sorted(scandir(path), key=lambda l: l.name):
				file_cnt = 0	# to check if directory has no files to list
				if entry.is_dir():	# dive into the subdirectories
					tree.append({'type': 'dir', 'path': entry.path, 'name': entry.name, 'indent': indent})
					if __ls__(entry.path, indent+1) == 0:
						tree.pop()
				else:	# check file formats by extension and magic number
					if self.ispcap(entry.path):
						tree.append({'type': 'pcap', 'path': entry.path, 'name': entry.name, 'indent': indent})
						file_cnt += 1
			return file_cnt
		# main method starts here
		global tree
		tree = []
		__ls__(self.filestruct.pcap, 0)
		return tree

	def ispcap(self, fname):
		'Check if file is PCAP'
		if fname[-5:] != '.pcap':
			return False
		try:
			with open(fname, 'rb') as f:
				magicnumber = f.read(4)
		except IsADirectoryError:
			return False
		if magicnumber != b'\xa1\xb2\xc3\xd4' and magicnumber != b'\xd4\xc3\xb2\xa1':
			return False
		return True

	def ls(self, pcap):
		'Return list of PCAP files from form. Make sure no directories are put in the file list.'
		if isinstance(pcap, str):
			pcap = [pcap]
		return [ i for i in pcap if self.ispcap(i) ]

	def pcaprunner(self, proname, pcapfiles):
		'Generate statistics from a list of pcap files'
		netflowjson = path.join(self.filestruct.netflow, '%s_%s.json' % (self.filestruct.timestampnow(), proname))
		pcapfiles_clean = self.ls(pcapfiles)
		cmd = [self.filestruct.pcaprunner, '-j', netflowjson]
		cmd.extend(pcapfiles_clean)
		return Popen(cmd), pcapfiles_clean, netflowjson

	def ipgrep(self, proname, pattern, pcapfiles):
		'Grep IP packets out of given PCAP files'
		outpcap = path.join(self.filestruct.netflow, self.filestruct.timestampnow(), proname, '.pcap')
		pcapfiles_clean = self.ls(pcapfiles)
		cmd = [self.filestruct.ipgrep, pattern, outpcap]
		cmd.extend(pcapfiles_clean)
		return Popen(cmd), pcapfiles_clean, outpcap

