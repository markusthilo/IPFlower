#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# IPAddresses

from maxminddb import open_database
from os import path
from ipaddress import IPv4Address, IPv6Address, ip_address

class GeoLite2:
	'Class to use MaxMind GeoLite2 databases City and ASN'

	def __init__(self):
		'Create address from given string'
		self.dir = path.join(path.dirname(path.realpath(__file__)).rsplit('/', 2)[0], 'geolite2')	# root dir is 2 levels up from this script
		try:	# try to open databases
			self.asn = open_database(path.join(self.dir, 'GeoLite2-ASN.mmdb'))
		except:
			self.asn = None
		try:
			self.country = open_database(path.join(self.dir, 'GeoLite2-Country.mmdb'))
		except:
			self.country = None

	def get(self, addr):
		'Get infos to given IP address'
		if isinstance(addr, str):
			addr = ip_address(addr)
		data = dict()
		if self.country != None:
			if addr.is_private:
				data['country'] = '-'
				data['cc'] = 'private'
			else:
				country_data = self.country.get(addr)
				try:
					data['country'] = country_data['country']['names']['en']
					data['cc'] = country_data['country']['iso_code']
				except (KeyError, TypeError):
					data['country'] = '-'
					data['cc'] = 'unknown'
		if self.asn != None:
			if addr.is_private:
				if self.country == None:
					data['aso'] = 'Private IP Address'
				else:
					data['aso'] = '-'
				data['asn'] = '-'
			else:
				asn_data = self.asn.get(addr)
				try:
					data['aso'] = asn_data['autonomous_system_organization']
					data['asn'] = asn_data['autonomous_system_number']
				except (KeyError, TypeError):
					data['aso'] = '-'
					data['asn'] = '-'
		return data
