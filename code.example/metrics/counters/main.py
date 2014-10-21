#!/usr/bin/env python
# coding: utf-8

from statsd import statsd
import time
import random

def _main():

	while True:

		statsd.increment('mymetric.counter1', random.randint(1, 3))
		statsd.increment('mymetric.counter2', random.randint(1, 3))

		statsd.increment('mymetric.counters.0001', random.randint(1, 3))
		statsd.increment('mymetric.counters.0002', random.randint(1, 3))

		print '.'
		interval = 1 + random.random()
		time.sleep(interval)

_main()

