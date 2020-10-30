#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from datetime import datetime

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
