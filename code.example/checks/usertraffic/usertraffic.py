#!/opt/datadog-agent/embedded/bin/python
# coding: utf-8
#
# Agent Check のテスト中...
#
# TODO: _main() から実行できるようにしたい...
# → sudo できるからまあいいか...
#    [# sudo -u dd-agent dd-agent check usertraffic]
#
#
#



import sys
sys.path.append('/opt/datadog-agent/agent')
import socket
import subprocess
from checks import AgentCheck


class UserTrafficCheck(AgentCheck):

	@staticmethod
	def _read_port_number(current_chain, field):

		if current_chain == 'INPUT':
			pos = field.find('dpt:')
			if 0 <= pos:
				return field[pos + 4:]
		elif current_chain == 'OUTPUT':
			pos = field.find('spt:')
			if 0 <= pos:
				return field[pos + 4:]
			# if field.startswith('spt:'):
				# return field[4:]
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

			#
			# TODO: ここに処理を書かず、関数に分離すること
			#
			
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
				num = int(fields[0])
				port = UserTrafficCheck._read_port_number(current_chain, line)
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

def _println(*args):
	for x in args:
		sys.stdout.write(x)
	print

if __name__ == '__main__':

	if False:
		check, instances = UserTrafficCheck.from_yaml(
				'/etc/dd-agent/conf.d/usertraffic.yaml')
		for instance in instances:
			check.check(instance)
			print 'OK.'

	if True:
		result = UserTrafficCheck._netfilter()
		import json
		print json.dumps(result, indent=4)
		for chain, entries in result.iteritems():
			for number, item in entries.iteritems():
				key, bytes, tags = UserTrafficCheck._analyze_item(chain, item)
				_println('key=[', str(key), '], bytes=[', str(bytes), '], tags=', str(tags))
