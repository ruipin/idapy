"""
Singleton meta-class
"""

class Singleton(object):
	def __new__(cls, *args, **kwargs):
		# Return existing instance if already exists (singleton)
		it = cls.__dict__.get("__it__")
		if it is not None:
			return it

		# Allocate and store singleton instance
		cls.__it__ = it = object.__new__(cls)

		# Initialize
		it.__init_singleton__(*args, **kwargs)

		return it


	def __init_singleton__(self, *args, **kwargs):
		pass