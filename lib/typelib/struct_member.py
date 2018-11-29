"""
Abstract IDAPython Struct Member Class
"""

import logging

from .c_type import CType

from ida_idaapi import BADADDR
import ida_struct


class StructMember(object):
	""" Initialization """
	def __init__(self, struct, **kwargs):
		self.struct = struct
		self.struct.log.debug("kwargs = %s", str(kwargs))
		
		self._pick_offset(kwargs)
		self._pick_name(kwargs)
		self.log = struct.log.getChild(self.name)

		self._pick_type(kwargs)


	def _pick_offset(self, kwargs):
		# Calculate offset
		if "offset" in kwargs:
			self.offset = kwargs["offset"]
		else:
			self.offset = self.struct.size


	def _pick_name(self, kwargs):
		# Decide on field name
		if "name" in kwargs:
			self.name = kwargs["name"]
		elif "offset" in kwargs:
			self.name = "field_{:x}".format(kwargs["offset"])
		else:
			raise RuntimeError("StructMember requires a 'name' parameter")


	def _pick_type(self, kwargs):
		if "ctype" not in kwargs:
			raise ValueError("StructMember requires a 'ctype' parameter")

		self.c_type = CType(kwargs["ctype"])



	""" IDA """
	def _get_create_flags(self):
		if self.c_type.is_struct:
			return 0
	
		size = self.ctype.size
		if size == 8:
			return ida_bytes.FF_QWORD
		elif size == 4:
			return ida_bytes.FF_DWORD
		elif size == 2:
			return ida_bytes.FF_WORD
		elif size == 1:
			return ida_bytes.FF_BYTE
		else:
			raise RuntimeError("Unimplemented field size '{}'".format(size))


	def _prepare_ida_type(self):
		sptr = self.struct.sptr
		
		# Create structure member
		if ida_struct.add_struc_member(sptr, self.name, self.offset, 0, None, self.size) != ida_struct.STRUC_ERROR_MEMBER_OK:
			raise RuntimeError("Could not create struct member '{}'".format(self.name))

		# Get member pointer
		self.mptr = ida_struct.get_member_by_name(sptr, self.name)

		# set type
		ida_struct.set_member_tinfo(sptr, self.mptr, self.offset, self.tif, 0)
		
		self.log.info("Created struct member '%s' of size %d at offset %d", self.hierarchy, self.size, self.offset)


	def _validate_ida_type(self):
		# Name
		m_name = ida_struct.get_member_name(self.mptr.id)
		if m_name != self.name:
			self.log.warn("validate_ida_type: name mismatch. Expected '%s' but got '%s'", self.name, m_name)
			return False

		# Offset
		if self.mptr.soff != self.offset:
			self.log.warn("validate_ida_type: offset mismatch. Expected %d but got %s", self.offset, str(self.mptr.soff))
			return False

		# Size
		msize = self.mptr.eoff - self.mptr.soff
		if msize != self.size:
			self.log.warn("validate_ida_type: size mismatch. Expected %d but got %d", self.size, msize)
			return False

		self.log.debug("validate_ida_type: found match for '%s'", self.hierarchy)
		return True


	def _set_mptr(self, mptr):
		self.mptr = mptr



	""" Properties """
	@property
	def size(self):
		return self.c_type.size

	@property
	def offset_end(self):
		return self.offset + self.size

	@property
	def type_name(self):
		return self.c_type.name

	@property
	def hierarchy(self):
		return "{}.{}".format(self.struct.name, self.name)

	@property
	def tif(self):
		return self.c_type.tif

	def __str__(self):
		return self.name
