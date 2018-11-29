"""
Abstract IDAPython Struct Class

Automatically handles creating a type definition and accessing existing structures
"""

import logging
from collections import OrderedDict
from ..utils.singleton import Singleton

from .struct_member import StructMember

import ida_kernwin
import ida_struct
from ida_idaapi import BADADDR

class BaseStruct(Singleton):
	""" IDA name for this struct type. If empty, the class name is used """
	NAME = None

	""" Schema for this struct type"""
	SCHEMA = None

	""" Constructor """
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



	""" Initialization """
	def __init_singleton__(self, *args, **kwargs):
		self.log = logging.getLogger(self.__class__.__name__)

		self.size = 0
		self.sid  = None
		self.sptr = None

		self._parse_schema()
		self._prepare_ida_type()


	def _parse_schema(self):
		schema = self.schema

		if hasattr(self, "members") and self.members is not None:
			raise RuntimeError("Called _parse_schema with members already present")

		self.members = OrderedDict()
		self.members_array = []

		for d in schema:
			memb = StructMember(self, **d)
			self._register_member(memb)


	def _register_member(self, memb):
		if memb.name in self.members:
			raise RuntimeError("Member with name {} already present in structure".format(memb.name))

		self.members_array.append(memb)
		self.members[memb.name] = memb

		offset_end = memb.offset_end
		if offset_end > self.size:
			self.size = offset_end


	def _get_sptr(self):
		self.sptr = ida_struct.get_struc(self.tid)
		if self.sptr is None or self.sptr == BADADDR:
			raise RuntimeError("Could not obtain '{}' sptr (tid={})".format(self.name, self.tid))



	""" IDA Type """
	def _validate_ida_type(self):
		# type ID
		if self.tid is None or self.tid is BADADDR:
			self.log.warn("validate_ida_type: tid=%s is invalid", str(self.tid))
			return False

		# struc_t pointer
		ida_sptr = ida_struct.get_struc(self.tid)
		if ida_sptr.id != self.sptr.id:
			self.log.warn("validate_ida_type: sptr.id mismatch. Got %s but expected %s", str(ida_sptr.id), str(self.sptr.id))
			return False

		# Size
		ida_size = ida_struct.get_struc_size(ida_sptr)
		if ida_size != self.size:
			self.log.warn("validate_ida_type: size mismatch. Got %s but expected %s", str(ida_size), str(self.size))
			return False

		# members
		count = 0
		ida_memb = self.sptr.members # first member
		while True:
			found = False
			ida_name = ida_struct.get_member_name(ida_memb.id)

			for memb in self.members_array:
				if memb.name != ida_name:
					continue

				found = True

				memb._set_mptr(ida_memb)
				if not memb._validate_ida_type():
					self.log.warn("validate_ida_type: field '%s' failed validation", memb.name)
					return False

			if not found:
				self.log.warn("validate_ida_type: found unexpected member '%s'", str(ida_name))
				return False

			count += 1

			next_idx = ida_struct.get_next_member_idx(self.sptr, ida_memb.soff) # next member index
			if next_idx == -1:
				break

			ida_memb = self.sptr.get_member(next_idx) # next member

		# member count
		if count != len(self.members_array):
			self.log.warn("validate_ida_type: incorrect number of members. Got %d, expected %d", count, len(self.members_array))
			return False

		self.log.debug("validate_ida_type: found match for '%s'", self.hierarchy)
		return True


	def _prepare_ida_type(self):
		if hasattr(self, "tid") and self.tid is not None:
			raise RuntimeError("May not call _prepare_ida_type twice")

		# Find existing structure
		self.tid = ida_struct.get_struc_id(self.name)

		if self.tid != BADADDR:
			# Grab structure pointer
			self._get_sptr()

			# Struct with given name already exists, validate it
			if self._validate_ida_type():
				self.log.info("Found struct '%s' with ID %d", self.name, self.tid)
				return # Successful

			# Existing struct not valid, ask user whether to overwrite
			query = ida_kernwin.ask_yn(ida_kernwin.ASKBTN_NO, "A structure named '{}' already exists but does not match the needed format. Do you wish to overwrite it?".format(self.name))
			if query != ida_kernwin.ASKBTN_YES:
				raise RuntimeError("User cancelled operation")

			# Delete existing struct
			if not ida_struct.del_struc(self.sptr):
				raise RuntimeError("Could not delete existing structure '{}'".format(self.name))
			self.log.info("Deleted struct '%s' (ID=%d)", self.name, self.tid)
			self.tid  = None
			self.sptr = None

		# Create struct
		self.tid = ida_struct.add_struc(BADADDR, self.name)
		if self.tid is None or self.tid == BADADDR:
			raise RuntimeError("Could not create structure '{}'".format(self.name))

		# Grab structure pointer
		self._get_sptr()

		# Create members
		for f in self.members_array:
			f._prepare_ida_type()

		self.log.info("Created struct '%s' of size %d", self.name, self.size)



	""" Attributes """
	# Name
	@property
	def name(self):
		nm = self.__class__.NAME
		if nm is None:
			return self.__class__.__name__
		else:
			return nm

	@property
	def hierarchy(self):
		return self.name

	def __str__(self):
		return self.name


	# Schema
	@property
	def schema(self):
		schema = self.__class__.SCHEMA
		if schema is None:
			raise ValueError("Classes inheriting from base_struct must declare a schema 'SCHEMA'")
		return schema


	# Size
	def __len__(self):
		return self.size


	# Nr. of members
	@property
	def member_count(self):
		return len(self.members_array)



	""" Create StructInstance object for a given address """
	def at(self, ea):
		# TODO: Implement StructInstance helper class
		raise NotImplementedError()

	def __call__(self, *args, **kwargs):
		return self.at(*args, **kwargs)