#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from datetime import datetime

class BasicOutput:
	'Base for output classes'

	def humantime(self, ts):
		'Create full readable timestamp as string'
		return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f')
