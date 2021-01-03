#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Markus Thilo'
__version__ = '0.8-20201217'
__license__ = 'GPL-3'

from lib.zeekstats import Zeek
from lib.iprunner import IPRunner
from lib.basicinout import CSVGenerator
from lib.netvis import NetVis
from argparse import ArgumentParser, FileType
from sys import stdout as StdOut
from sys import stderr as StdErr
from sys import exit as SysExit
from configparser import ConfigParser
from pathlib import Path

CONFIG = {
	geolite2dir: '.',
	geolite2country: 'GeoLite2-Country.mmdb',
	geolite2asn: 'GeoLite2-ASN.mmdb',
	visjsdir: 'visjs'
}

ZEEK_NO_PORTS = ('z', 'zeek', 'zeek_no_ports')
ZEEK_PORTS = ('zp', 'zeek_ports')
IPRUNNER = ('i', 'ip', 'iprunner')
LIST = '''
z / zeek / zeek_no_ports:
	Display conn.log from ZEEK ignoring ports.

zp / zeek_ports:
	Display conn.log from ZEEK, differentiate by server ports (id.resp_p).
	For this no visualisation is available.

i / ip / iprunner:
	Display TSV file from IPRUNNER.
	For files created with -s or -g no visualisation is available.
'''

if __name__ == '__main__':	# start here if called as application
	argparser = ArgumentParser(description='Visualize netflow data')

	argparser.add_argument('-b', '--blacklist', nargs=1, type=FileType('rt'),
<<<<<<< HEAD
		help='File with blacklisted = suppressed IP addresses', metavar='FILE'
	)
	argparser.add_argument('-c', '--config', nargs=1, type=FileType('rt'),
		help='Cofiguration File', metavar='FILE'
	)
	argparser.add_argument('-d', '--outdir', type=FileType('w'), default=StdOut,
		help='File to write', metavar='FILE'
=======
		help='File with blacklisted IP addresses', metavar='FILE'
	)
	argparser.add_argument('-c', '--noheadline', action='store_true',
		help='Give headlines = column names on CSV output'
>>>>>>> c667a23a58649419aa394e887dfdf74f7c12f39c
	)
	argparser.add_argument('-g', '--grep', dest='grep',
		help='Target IP address', metavar='IP_ADDRESS/LINK',
		type=str
	)
<<<<<<< HEAD
	argparser.add_argument('-i', '--in', dest='filetype', default='z',
		help='Type of input file(s), default is zeek', metavar='SWITCH'
=======
	argparser.add_argument('-i', '--reverse', action='store_true',
		help='Reverse order on TSV output'
>>>>>>> c667a23a58649419aa394e887dfdf74f7c12f39c
	)
	argparser.add_argument('-m', '--max', type=int,
		help='Maximum number of IP addresses to visualize', metavar='INTEGER'
	)
<<<<<<< HEAD
	argparser.add_argument('-n', '--noheadline', action='store_true',
		help='Give headlines = column names on CSV output'
	)
	argparser.add_argument('-o', '--out', default='t',
		help='Output Format, default is tsv', metavar='SWITCH'
	)
	argparser.add_argument('-r', '--reverse', action='store_true',
		help='Reverse order on TSV output'
=======
	argparser.add_argument('-r', '--readable', action='store_true',
		help='Give better readable sizes'
	)
	argparser.add_argument('-t', '--in', dest='filetype', default='z',
		help='Type of input an calculation - use -t l or -t list to get details', metavar='SWITCH'
>>>>>>> c667a23a58649419aa394e887dfdf74f7c12f39c
	)
	argparser.add_argument('-u', '--unixtime', action='store_true',
		help='Unix timestamps (seconds and microseconds) on CSV output'
	)
	argparser.add_argument('-v', '--vis', action='store_true',
		help='Generate HTML/JavaScript for VISJS (default is TSV output)'
	)
	argparser.add_argument('-w', '--outfile', type=FileType('w'), default=StdOut,
		help='File to write', metavar='FILE'
	)
<<<<<<< HEAD
	argparser.add_argument('-y', '--bytes', action='store_true',
		help='Data volume in pure bytes (no B, KB, MB etc.) on CSV output'
	)
	argparser.add_argument('infiles', nargs='+', type=FileType('rt'),
		help='File(s) to read, at least one is required', metavar='FILE'
=======
	argparser.add_argument('infiles', nargs='*', type=FileType('rt'),
		help='File(s) to read,', metavar='FILE'
>>>>>>> c667a23a58649419aa394e887dfdf74f7c12f39c
	)
	args = argparser.parse_args()
	if args.filetype.lower() in ('l', 'list'):
		print(LIST)
		SysExit(0)
	if args.infiles == []:
		print('Error: At least one input file is required.', file=StdErr)
		SysExit(1)
	if args.filetype.lower() in ZEEK_NO_PORTS:
		stats = Zeek(
			args.infiles,
<<<<<<< HEAD
			config,
=======
			ports = False,
>>>>>>> c667a23a58649419aa394e887dfdf74f7c12f39c
			grep=args.grep,
			blacklist=args.blacklist
		)
	elif args.filetype.lower() in ZEEK_PORTS:
		stats = Zeek(
			args.infiles,
			ports = True,
			grep=args.grep,
			blacklist=args.blacklist
		)
	elif args.filetype.lower() in IPRUNNER:
		stats = IPRunner(
			args.infiles,
			config,
			grep=args.grep,
			blacklist=args.blacklist
		)
	else:
		print('Error: Unknown input file type.', file=StdErr)
		SysExit(1)
<<<<<<< HEAD
	if 		
		
		
		
		
	if args.out.lower() in ('t', 'tsv'):
=======
	if args.vis:
		if not stats.vis_available:
			print('Error: Visualisation is not available.', file=StdErr)
			SysExit(1)
		netvis = NetVis(args.outfile, stats, maxnodes=args.max)
		netvis.write()
	else:
>>>>>>> c667a23a58649419aa394e887dfdf74f7c12f39c
		csv = CSVGenerator(
			args.outfile,
			stats,
<<<<<<< HEAD
			headline=not args.noheadline,
=======
			noheadline=args.noheadline,
>>>>>>> c667a23a58649419aa394e887dfdf74f7c12f39c
			maxout=args.max,
			reverse=args.reverse,
			unixtime=args.unixtime,
			humanreadable=args.readable
		)
		csv.write()
	SysExit(0)

