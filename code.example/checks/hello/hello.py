from checks import AgentCheck
import random

class HelloCheck(AgentCheck):
	def check(self, instance):
		self.gauge('hello.world', random.random() * 1000)

