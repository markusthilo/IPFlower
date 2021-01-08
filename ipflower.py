#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Markus Thilo'
__version__ = '0.9-20210104'
__license__ = 'GPL-3'

from lib.zeekstats import Zeek
from lib.iprunner import IPRunner
from lib.basicinout import CSVGenerator
from lib.netvis import NetVis
from argparse import ArgumentParser, FileType
from sys import stdout as StdOut
from sys import stderr as StdErr
from sys import exit as SysExit
from os import path
from configparser import ConfigParser
from pathlib import Path

if __name__ == '__main__':	# start here if called as application
	homeconf = path.join(path.expanduser('~'), '.config', 'ipflower.conf')	#  ~/.config/ipflower.conf
	mainconf = path.join(path.dirname(path.abspath(__file__)), 'ipflower.conf')	# IPFlower/ipflower.conf
	argparser = ArgumentParser(description='Analize netflow data')
	argparser.add_argument('-b', '--blacklist', nargs=1, type=FileType('rt'),
		help='File with blacklisted = suppressed IP addresses', metavar='FILE'
	)
	argparser.add_argument('-c', '--config', type=str,
		help='Cofiguration File', metavar='FILE'
	)
	argparser.add_argument('-d', '--outdir', type=str,
		help='Directory to write HTML and vis.js node-modules', metavar='DIRECTORY'
	)
	argparser.add_argument('-g', '--grep',	type=str,
		help='Target IP address', metavar='IP_ADDRESS/LINK',
	)
	argparser.add_argument('-i', '--reverse', action='store_true',
		help='Reverse order on TSV output'
	)
	argparser.add_argument('-m', '--max', type=int,
		help='Maximum number of IP addresses to visualize', metavar='INTEGER'
	)
	argparser.add_argument('-n', '--noheadline', action='store_true',
		help='Suppress headlines = column names on CSV output'
	)
	argparser.add_argument('-t', '--type', dest='datatype',
		help='Type of input data and calculation - use -t l or -t list to get details', metavar='STRING'
	)
	argparser.add_argument('-u', '--unixtime', action='store_true',
		help='Unix timestamps (seconds and microseconds) on CSV output'
	)
	argparser.add_argument('-v', '--vis', action='store_true',
		help='Generate HTML/JavaScript for VISJS (default is TSV output)'
	)
	argparser.add_argument('-w', '--outfile', type=FileType('w'),
		help='File to write', metavar='FILE'
	)
	argparser.add_argument('-y', '--bytes', action='store_true',
		help='Data volume in bytes (no B, KB, MB etc.) on CSV output'
	)
	argparser.add_argument('infiles', nargs='*', type=FileType('rt'),
		help='File(s) to read, at least one is required', metavar='FILE'
	)
	args = argparser.parse_args()
	config = ConfigParser()	# generate configuration object
	configfile = None
	if args.config == None:
		for filename in (homeconf, mainconf):
			if path.exists(filename):
				configfile = filename
				break
	elif path.exists(args.config):
		configfile = args.config
	else:
		print('Error: Could not read configuration file.', file=StdErr)
		SysExit(1)
	if configfile == None:	# if no configfile, generate config
		config['geolite2'] = {
			'country': path.join(path.abspath(__file__), 'geolite2', 'GeoLite2-Country.mmdb'),
			'asn': path.join(path.abspath(__file__),'geolite2', 'GeoLite2-ASN.mmdb')
		}
		config['visjs'] = {'basedir': path.join(path.abspath(__file__), 'visjs')}
		config['pixmaps'] = {'basedir': path.join(path.abspath(__file__),'pixmaps')}
		for filename in (homeconf, mainconf):	# write config file
			try:
				with open(filename, 'w') as f:
					config.write(f)
				break
			except FileNotFoundError:
				pass
	else:
		config.read(configfile)
	if args.datatype == None:
		argparser.print_help(StdErr)
		SysExit(1)
	if args.datatype.lower() in ('l', 'list', 'help'):
		print('''
Types of input file(s):

	z / zeek / zeek_no_ports:
		Display conn.log from ZEEK ignoring ports.

	zp / zeek_ports:
		Display conn.log from ZEEK, differentiate by server ports (id.resp_p).
		For this no visualisation is available.

	i / ip / iprunner:
		Display TSV file from IPRUNNER.
		For files created with -s or -g no visualisation is available.
''')
		SysExit(0)
	if args.infiles == []:
		print('Error: At least one input file is required.', file=StdErr)
		SysExit(1)
	if args.datatype.lower() in ('z', 'zeek', 'zeek_no_ports'):
		stats = Zeek(
			args.infiles,
			grep=args.grep,
			blacklist=args.blacklist
		)
	elif args.datatype.lower() in ('zp', 'zeek_ports'):
		stats = Zeek(
			args.infiles,
			ports = True,
			grep=args.grep,
			blacklist=args.blacklist
		)
	elif args.datatype.lower() in ('i', 'ip', 'iprunner'):
		stats = IPRunner(
			args.infiles,
			grep=args.grep,
			blacklist=args.blacklist
		)
	else:
		print('Error: Unknown input file type.', file=StdErr)
		SysExit(1)
	if args.vis:	# network visualisation
		if not stats.vis_available:
			print('Error: Visualisation is not available.', file=StdErr)
			SysExit(1)
		netvis = NetVis(stats, config, maxnodes=args.max)
		if args.outdir != None:
			netvis
		netvis.write(args.outfile)
	else:	# csv/tsv
		if args.outfile = None:
			outfile = StdOut
		else:
			outfile = args.outfile
		csv = CSVGenerator(
			stats,
			config,
			noheadline=args.noheadline,
			maxout=args.max,
			reverse=args.reverse,
			unixtime=args.unixtime,
			intbytes=args.bytes
		)
		csv.write(outfile)
	SysExit(0)

