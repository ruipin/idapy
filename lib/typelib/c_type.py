"""
Abstract IDAPython C type Class
"""

import logging

import ida_typeinf
import ida_nalt


class CType(object):
	""" Initialization """
	def __init__(self, c_name):
		self.c_name = c_name
		self.log = logging.getLogger(self.c_name)
		
		self.tif = None

		# TODO: What about offset data-types?
		self._parse_c_name()



	""" IDA Type """
	def _parse_c_name(self):
		if self.tif is not None:
			raise RuntimeError("May not call _parse_c_name twice")

		# use ida_typeinf.parse_decl to obtain a tinfo_t object
		tif = ida_typeinf.tinfo_t()
		decl = "{} x;".format(self.c_name)

		ida_typeinf.parse_decl(tif, None, decl, ida_typeinf.PT_TYP)
		if tif.empty():
			raise RuntimeError("Could not parse type '{}'".format(self.c_name))
		self.tif = tif

		self



	""" Properties """

	# Size
	@property
	def size(self):
		return self.tif.get_size()

	def __len__(self):
		return self.size

	# Name
	@property
	def name(self):
		return str(self.tif)

	def __str__(self):
		return self.name

	# Struct
	@property
	def is_struct(self):
		return self.name.startswith("struct")