# coding: utf-8
#
# Agent Check のテスト中...
#
#
#
#
#
#
#



import socket
import subprocess
from checks import AgentCheck


class UserTrafficCheck(AgentCheck):

	@staticmethod
	def _read_port_number(current_chain, field):

		if current_chain == 'INPUT':
			if field.startswith('dpt:'):
				return field[4:]
		elif current_chain == 'OUTPUT':
			if field.startswith('spt:'):
				return field[4:]

		return 0

	@staticmethod
	def _netfilter():

		#
		# TODO: 'service iptables status' に変更すること
		#
		command = ['sudo', '-u', 'root', '/sbin/iptables',
				'--list', '-nvx', '--line-numbers']

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

				#
				# changing current chain
				#
				current_chain = fields[1]

				result[current_chain] = {}

			elif 11 <= len(fields) and fields[3] == 'ACCEPT':

				#
				# reading rule and status
				#
				num = fields[0]
				port = UserTrafficCheck._read_port_number(current_chain, fields[11])
				if port == 0:
					continue
				new_entry = {
					'bytes': fields[2],
					'protocol': fields[4],
					'port': port,
				}

				result[current_chain][num] = new_entry

		stream.close()
		return result

	@staticmethod
	def _analyze_item(direction, item):

		#
		# chain
		#
		direction = {'INPUT': 'in', 'OUTPUT': 'out'}.get(direction)
		if direction is None:
			return '', 0

		#
		# protocol
		#
		protocol = item.get('protocol')
		if not {'tcp': 1, 'udp': 1}.has_key(protocol):
			return '', 0

		#
		# bytes
		#
		if not item.has_key('bytes'):
			return '', 0
		bytes = int(item['bytes'])

		#
		# port
		#
		if not item.has_key('port'):
			return '', 0

		key = 'user.net.traffic'

		tags = [
			'protocol:' + item['protocol'],
			'direction:' + direction,
			'port:' + str(item['port'])
		]

		return key, bytes, tags

	def check(self, instance):

		#
		# 長いコンピューター名
		#
		hostname = socket.gethostname()

		#
		# iptables を実行して結果を読み取り(テスト中)
		#
		result = UserTrafficCheck._netfilter()

		#
		# 取り出し(テスト中)
		#
		for chain, entries in result.iteritems():

			for number, item in entries.iteritems():

				key, bytes, tags = UserTrafficCheck._analyze_item(chain, item)

				if key is None or key == '':
					continue

				tags = ['host:' + hostname] + tags

				#
				# sending
				#
				self.gauge(key, bytes, tags = tags)

		#
		# exit
		#
		return
