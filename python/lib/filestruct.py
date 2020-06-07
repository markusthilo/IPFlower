#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Complete filestructure an localize where to find which file

from cherrypy import log
from maxminddb import open_database
from datetime import datetime
from os import path, name, mkdir, remove, listdir
from shutil import rmtree
from re import compile as rcompile
from subprocess import run

class FileStruct:
	'File Structure of Netflower'

	BLOCKSIZE = 8192

	def __init__(self):
		'Define where to find which file and databases'
		log('Creating or updating file structure')
		self.root = path.dirname(path.realpath(__file__)).rsplit('/', 2)[0]	# root dir is 2 levels up from this script
		self.pixmaps = path.join(self.root, 'pixmaps')	# set paths
		self.javascript = path.join(self.root, 'javascript')
		self.c = path.join(self.root, 'c')
		self.tmp = self.mkdir('tmp')	# create directories and set paths
		self.projects = self.mkdir('projects')
		self.pcap = self.mkdir('pcap')
		self.netflow = self.mkdir('netflow')
		try:	# try to open databases
			self.mmdb_asn = open_database(path.join(self.root, 'db', 'GeoLite2-ASN.mmdb'))
			log('Using GeoLite2-ASN')
		except:
			self.mmdb_asn = None
		try:
			self.mmdb_city = open_database(path.join(self.root, 'db', 'GeoLite2-City.mmdb'))
			log('Using GeoLite2-City')
		except:
			self.mmdb_city = None
		self.bin = self.mkdir('bin')
		if name == 'nt':	# check operating system - windows or a real one... :-)
			self.compiler = 'mingw64.exe'
			self.pcaprunner = path.join(self.bin, 'pcaprunner.exe')
			self.ipgrep = path.join(self.bin, 'ipgrep.exe')
			self.compile('pcaprunner4mingw64.c', self.pcaprunner)
			self.compile('ipgrep4mingw64.c', self.ipgrep)
		else:
			self.compiler = 'gcc'
			self.pcaprunner = path.join(self.bin, 'pcaprunner')
			self.ipgrep = path.join(self.bin, 'ipgrep')
			self.compile('pcaprunner.c', self.pcaprunner)
			self.compile('ipgrep.c', self.ipgrep)

	def timestampnow(self):
		'Give current time as string to use in filenames'
		return datetime.now().strftime('%Y%m%d_%H%M%S')

	def mkdir(self, dirname):
		'Create directory if not present'
		dirpath = path.join(self.root, dirname)
		if not path.isdir(dirpath):
			mkdir(dirpath)
		return dirpath

	def searchdir(self, topdir, regex):
		'Search for directory by regular expression'
		matchdir = None
		pattern = rcompile(regex)
		for i in listdir(topdir):
			if pattern.match(i):
				matchdir = path.join(topdir, i)
				break
		return matchdir

	def rm(self, paths):
		'Remove file(s)'
		if not isinstance(paths, list):
			paths = [paths]
		for i in paths:
			remove(i)

	def upload(self, upfiles):
		'Upload file(s)'
		error = False
		if not isinstance(upfiles, list):
			upfiles = [upfiles]
		for i in upfiles:
			dstfile = path.join(self.pcap, i.filename)
			if path.exists(dstfile):
				error = True
			else:
				try:
					with open(dstfile, 'wb') as f:
						while True:
							block = i.file.read(self.BLOCKSIZE)
							if not block:
								break
							f.write(block)
				except:
					error = True
		return error

	def compile(self, srcfname, dstpath):
		'Compile C file if no executable is present'
		srcpath = path.join(self.c, srcfname)
		if not path.exists(dstpath):
			log('Compiling ' + srcfname)
			proc = run([self.compiler, '-o', dstpath, srcpath])
			if proc.returncode == 1:
				raise RuntimeError('Could not build %s from C source file. Is gcc / mingw64 installed?' % dstpath)
			log('Done')
