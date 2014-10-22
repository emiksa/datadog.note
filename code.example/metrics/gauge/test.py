#!/usr/bin/env python
# coding: utf-8
#
#
#
#
#
#
# DATADOG に gauge を送るテスト
# 2014-10-21: まだ試験中です。
#
#
#
#
#
#
#




import sys
import subprocess
import json
import codecs
import random
from statsd import statsd



def _println(*arguments):

	out = codecs.getwriter('utf-8')(sys.stdout)
	for x in arguments:
		s = '' + x
		out.write(s)
	out.write("\n")

def _read_port_number(current_chain, field):

	if current_chain == 'INPUT':
		if field.startswith('dpt:'):
			return field[4:]
	elif current_chain == 'OUTPUT':
		if field.startswith('spt:'):
			return field[4:]
	return 0

def _netfilter():

	command = ['iptables', '--list', '-nvx', '--line-numbers']
	stream = subprocess.Popen(
			command,
			stdout=subprocess.PIPE).stdout

	current_chain = ''

	result = {}
	result['INPUT'] = {}
	result['OUTPUT'] = {}
	result['FORWARD'] = {}

	for line in stream:

		line = line.strip()
		if line == '':
			continue

		fields = line.split()

		if fields[0] == 'Chain':
			current_chain = fields[1]
			result[current_chain] = {}
		elif 11 <= len(fields) and fields[3] == 'ACCEPT':
			num = fields[0]
			new_entry = {
				'bytes': fields[2],
				'protocol': fields[4],
				'port': _read_port_number(current_chain, fields[11]),
			}
			result[current_chain][num] = new_entry

	stream.close()
	return result

def _generate_key(direction, item):

	#
	# chain
	#
	direction = {'INPUT': 'in', 'OUTPUT': 'out'}.get(direction)
	if direction is None:
		_println('[warn]: invalid direction.')
		return '', 0

	#
	# protocol
	#
	protocol = item.get('protocol')
	if not {'tcp': 1, 'udp': 1}.has_key(protocol):
		_println('[warn]: unknown protocol')
		return '', 0

	#
	# bytes
	#
	if not item.has_key('bytes'):
		_println('[warn]: no length.')
		return '', 0
	bytes = int(item['bytes'])

	#
	# port
	#
	if not item.has_key('port'):
		_println('[warn]: unknown port.')
		return '', 0

	key = 'user.net.traffic.' + item['protocol'] + '.' + direction + '.' + str(item['port'])
	return key, bytes

def _execute():

	statsd.connect('localhost', 8125)

	result = _netfilter()

	for chain, entries in result.iteritems():

		for number, item in entries.iteritems():

			key, bytes = _generate_key(chain, item)
			if key is None or key == '':
				continue

			_println('[info]: send gauge=[', key, '], value=[', str(bytes), ']')
			# statsd.histogram(key, bytes)
			statsd.gauge(key, bytes)

	# _println(json.dumps(result, sort_keys=True, indent=4))

def _main():

	_execute()

_main()




