#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Base tools to work with netflow data

from os import path
from json import load
from datetime import datetime

class Netflow:
	'The netflow data generated by PCAPRUNNER'

	DEFAULT_HIGHPORT = 49152	# default start of dynamic / private / high ports
	TRAFFIC_SEPARATED = (	# traffic volume and amount of packets for src and dst separated
		'TCP_IN_PACKETS', 'UDP_IN_PACKETS', 'OTHER_IN_PACKETS',
		'TCP_OUT_PACKETS', 'UDP_OUT_PACKETS', 'OTHER_OUT_PACKETS',
		'ALL_PACKETS',
		'TCP_IN_VOLUME', 'UDP_IN_VOLUME', 'OTHER_IN_VOLUME',
		'TCP_OUT_VOLUME', 'UDP_OUT_VOLUME', 'OTHER_OUT_VOLUME',
		'ALL_VOLUME'
	)
	TRAFFIC_COMBINED = (	# traffic volume and amount of packets for src and dst combined
		'TCP_PACKETS', 'UDP_PACKETS', 'OTHER_PACKETS',
		'ALL_PACKETS',
		'TCP_VOLUME', 'UDP_VOLUME', 'OTHER_VOLUME',
		'ALL_VOLUME'
	)

	def __init__(self, pro):
		'Load netflow from JSON file that was generated by PCAPRUNNER'
		self.filestruct = pro.filestruct
		with open(path.join(pro.filestruct.netflow, pro.netflow), 'r') as f:
			self.data = load(f)
		for i in self.data:	# parse data
			for j in self.data[i]:
				for k in j:
					if k[-4:] == 'ADDR':
						j[k] = IpAddress(j[k], self.filestruct)
		self.max_volume = 0	# get the max volume of one single ip
		for i in self.data['singles']:
			if i['ALL_VOLUME'] > self.max_volume:
				self.max_volume = i['ALL_VOLUME']

	def merge(self, datasets, addthis):
		'Merge data of IP datasets, sum traffic amount and update timestamps'
		newset = datasets[0]	# 1st set is the base so ip adress(es) will kept from this
		if len(datasets) == 1:
			return newset
		for i in datasets[1:]:	# go through datasets to merge
			for j in addthis:	# add packets and traffic volume
				newset[j] += i[j]
			if j['FIRST_TS'] < newset['FIRST_TS']:	# check for new first seen / last seen
				newset['FIRST_TS'] = j['FIRST_TS']
			if j['LAST_TS'] > newset['LAST_TS']:
				newset['LAST_TS'] = j['LAST_TS']
		return newset

	def pick_single(self, addr_unkn, highport = DEFAULT_HIGHPORT):
		'Pick out data about one IP address'
		if isinstance(addr_unkn, IpV46) or isinstance(addr_unkn, IpAddress):
			ip = addr_unkn	# convert address if necessary
		else:
			ip = IpV46(addr_unkn)
		if ip == None:
			return None, None
		for single in self.data['singles']:	# find single in netflow data
			if single['ADDR'].addr == ip.addr:
				break
		else:
			return None, None
		ports = []
		highports = []
		for i in self.data['ports']:	# find ports in netflow data
			if i['ADDR'].addr == ip.addr:
				if i['PORT'] < highport:
					ports.append(i)
				else:
					highports.append(i)
		if len(highports) > 0:	# merge highports
			highport = self.merge(highports, self.TRAFFIC_SEPARATED)
			highport['PORT'] = 'HIGHPORTS'
			ports.append(highport)
		return single, ports

	def pick_link(self, link_unkn, highport = DEFAULT_HIGHPORT):
		'Pick out data about link'
		if isinstance(link_unkn, IpLink):	# convert given link if necessary
			link = link_unkn
		else:
			link = IpLink(link_unkn, self.filestruct)
		if link.addresses == None:
			return None, None
		allports = []	# find links in netflow data
		for i in (0, 1), (1, 0):
			for j in self.data['links']:
				if j['SRC_ADDR'].addr == link.addresses[i[0]].addr and j['DST_ADDR'].addr == link.addresses[i[1]].addr:
					allports.append(j)
					if len(allports) > 1:
						break
		high_both = []	# find links sparated by ports
		high_src = []
		high_dst = []
		ports = []
		lowports = set()
		for i in (0, 1), (1, 0):
			for j in self.data['raws']:
				if j['SRC_ADDR'].addr == link.addresses[i[0]].addr and j['DST_ADDR'].addr == link.addresses[i[1]].addr:
					if j['SRC_PORT'] >= highport and j['DST_PORT'] >= highport:
						high_both.append(j)
					elif j['SRC_PORT'] >= highport:
						high_src.append(j)
						lowports.add(j['DST_PORT'])
					elif j['DST_PORT'] >= highport:
						high_dst.append(j)
						lowports.add(j['SRC_PORT'])
					else:
						ports.append(j)
						lowports.update({j['SRC_PORT'], j['DST_PORT']})
		if len(high_both) > 0:
			ports.append(self.merge(high_both, self.TRAFFIC_COMBINED))
			ports[-1]['SRC_PORT'] = 'HIGHPORTS'
			ports[-1]['DST_PORT'] = 'HIGHPORTS'
		for i in lowports:
			for j in high_src:
				if j['DST_PORT'] == lowports:
					ports.append(self.merge(high_src, self.TRAFFIC_COMBINED))
					ports[-1]['SRC_PORT'] = 'HIGHPORTS'
			for j in high_dst:
				if j['SRC_PORT'] == lowports:
					ports.append(self.merge(high_dst, self.TRAFFIC_COMBINED))
					ports[-1]['DST_PORT'] = 'HIGHPORTS'
		return allports, ports
