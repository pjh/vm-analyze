#! /usr/bin/env python3.3
# Virtual memory analysis scripts.
# Developed 2012-2014 by Peter Hornyack, pjh@cs.washington.edu
# Copyright (c) 2012-2014 Peter Hornyack and University of Washington

from vm_regex import *
from pjh_utils import *
from simulate_segments_lib import *
from vm_mapping_class import *
import vm_common as vm
import os
import re
import shlex
import shutil
import sys

# Globals:

##############################################################################
##############################################################################
##############################################################################
# Strategies for fitting mappings into segments. The signature for each of
# these methods should be as follows:
# strategy_fn(length, at_addr, perms_key, old_perms_key, action):
#   length is the length of the mapping
#   at_addr is the integer address where the application requested that
#     this mapping be placed, or None if the application doesn't care.
#     This argument is currently unused...
#   start_addr is the integer address where the OS actually placed the
#     mapping. This value is important because it is used as a unique
#     identifier in calls like mprotect(), munmap(), etc.
#   prot_bools is a tuple of booleans for the protocol permissions; it
#     must be set for the map, remap, and protect actions.
#       (prot_r, prot_w, prot_x)
#   map_bools is a tuple of booleans for the mapping type; it must be set
#   for the map action, but not for other actions.
#       (map_s, map_anon)
#   action must be one of:
#     "map": add a new mapping
#     "remap": adjust a mapping's permissions (?) and/or length
#     "protect": adjust only the mapping's permissions
#     "unmap": remove an existing mapping
''' Skeleton for new strategies:
	if action == "map":
		print_error_exit(tag, ("not implemented yet: map"))
	elif action == "remap":
		print_error_exit(tag, ("not implemented yet: remap"))
	elif action == "protect":
		print_error_exit(tag, ("not implemented yet: protect"))
	elif action == "unmap":
		print_error_exit(tag, ("not implemented yet: unmap"))
	else:
		print_error_exit(tag, ("invalid action {0}").format(action))
'''

# Simulation: unlimited segments that are powers of 2.
# This is the "outer" method that may break up the original request into
# multiple smaller requests, which are passed to the "inner" method.
# This method may recursively call itself after sending a subrequest to
# the inner method; in this case, the only arguments that will change
# are length and start_addr.
def simulate_unlimited_segments_outer(proc_info, length, at_addr,
	start_addr, prot_bools, map_bools, action):
	tag = "simulate_unlimited_segments_outer"
	global strategy

	# length, start_addr and action are always required.
	assert length is not None
	assert start_addr is not None

	# Initialize segset dictionary: no restrictions on segment size,
	# so just use empty dict and add any key (segment size) to it later.
	# Other strategies may begin with a fixed set of segment sizes :)
	stats = proc_info.get_stats()
	segset = proc_info.get_segset()
	if segset is None:
		segset = dict()
		proc_info.set_segset(segset)

	end_addr = start_addr + length - 1
	print_debug(tag, ("[{0}, {1}]: entered outer method, action={2}").format(
		hex(start_addr), hex(end_addr), action))

	# Ok, here's what we do: find out what mappings, if any, overlap with
	# this request. Check exactly HOW they overlap, and then possibly
	# split up the request into multiple subrequests. When subrequests
	# are needed, we first dispatch a request to the "inner" simulation
	# for the first part of the request range, then recursively call
	# this outer function again with the remaining request range.
	#   *** When exactly do we need to create subrequests? The inner ***
	#       method knows how to handle requests that either don't
	#       overlap any existing mappings or both start and end
	#       within an existing mapping, so when it's possible
	#       that there are overlapping requests remaining that
	#       don't match these criteria, we have to create a smaller
	#       subrequest.

	overlapped = find_vm_mappings_in_range(proc_info, start_addr, end_addr)
	  # Note: we only actually use the first overlapped vm_mapping here;
	  # this method call could be optimized to not find the entire set
	  # of overlapped mappings, or this outer method could be made
	  # iterative instead of recursive (probably the better option...).

	if overlapped == []:
		# Great, just pass this request directly down to the inner method:
		print_debug(tag, ("[{0}, {1}]: no overlapping mappings found, "
			"so passing request directly to inner method").format(
			hex(start_addr), hex(end_addr)))
		simulate_unlimited_segments_inner(proc_info, length,
			at_addr, start_addr, prot_bools, map_bools, action)
		return

	s = []
	for (mapping, layout) in overlapped:
		s.append("\t{0}: [{1}]".format(layout, mapping.to_str()))
	s = "\n".join(s)
	print_debug(tag, ("[{0}, {1}]: overlapped mappings found:"
		"\n{2}").format(hex(start_addr), hex(end_addr), s))
	if len(overlapped) > 1:
		print_warning(tag, ("more than 1 overlapped mapping - check "
			"results carefully!").format())
		proc_info.add_to_stats("overlaps_multiple", 1)
		  # Note that currently these may be double-counted when a
		  # request overlaps more than two mappings, because they
		  # are handled recursively.
		  # In looking through the debug messages for these, many
		  # of them are a single 4096-byte guard page (---pa)
		  # followed by a normal (e.g. rw-pa) mapping.

	# IMPORTANT: in the following code, make sure to use end_addr() carefully!
	# If using it in arithmetic, need to take into account that it has already
	# performed the "- 1" part of "start_addr + length - 1".
	#   In other words, only start_addrs should be subtracted from start_addrs,
	#   and only lengths should be subtracted from lengths...
	(mapping, layout) = overlapped[0]
	if layout == "overlaps_left":
		# The request "extends" to the right of the existing mapping.
		# Strategy: first, remove the existing mapping. Then, add back the
		# beginning part of the existing mapping (via an explicit map action)
		# that is untouched by this current request.
		#   Actually, this can be achieved by calling the inner method with
		#   an UNMAP request for the latter (overlapped) part of the existing
		#   mapping; this will ensure that the vmatable and segset are both
		#   updated consistently.
		# Then, recurse (call the
		# outer function again) with the exact same request, which may now
		# hit one of the other layout cases below if there are other
		# overlapping mappings, or (most likely) just create a new mapping
		# that satisfies the original request. 
		sub_length = mapping.end_addr() + 1 - start_addr
		sub_action = "unmap"
		print_debug(tag, ("[{0}, {1}]: mapping {2}, sending subrequest "
			"[{3}, {4}] with sub_action {5}").format(hex(start_addr),
			hex(end_addr), layout, hex(start_addr),
			hex(start_addr + sub_length - 1), sub_action))
		print_error_exit(tag, "check this and remove to proceed!")
		if len(overlapped) > 1:
			print_error_exit(tag, ("check what should happen for "
				"multiple overlapped mappings here!"))
		if DEBUG:
			(prot_r, prot_w, prot_x) = prot_bools
			(map_s, map_anon) = map_bools
			if mapping.perms_key == vm.construct_perms_key2(prot_r, prot_w,
				prot_x, map_s, map_anon):
				print_warning(tag, ("Existing mapping overlaps_left with "
					"incoming request with SAME PERMISSIONS ({0}) - should "
					"these be combined into a single mapping??").format(
					mapping.perms_key))
		simulate_unlimited_segments_inner(proc_info, sub_length,
			at_addr=None, start_addr=start_addr, prot_bools=None,
			map_bools=None, action=sub_action)
		next_start_addr = start_addr   # nothing overlaps at start_addr now!
		print_debug(tag, ("[{0}, {1}]: recursing for request range "
			"[{2}, {3}], action={4}").format(hex(start_addr),
			hex(end_addr), hex(next_start_addr),
			hex(next_start_addr + length_left - 1), action))
		assert next_start_addr + length_left - 1 == end_addr
		print_error_exit(tag, "check this and remove to proceed!")
		if len(overlapped) > 1:
			print_error_exit(tag, ("check what should happen for "
				"multiple overlapped mappings here!"))
		# Possible actions: map, remap, unmap, protect. map should work
		# easily; the others are a little trickier since we've removed
		# the existing mapping.
		#   Possible solution: first explicitly MAP the remaining
		#   part of the request here (call outer method) before calling
		#   outer once again with the original action? Or just build
		#   this support into the inner method??
		#   Or, if original action is an unmap itself, then can skip
		#   over the part for the existing mapping (since we just
		#   unmapped it already), if that helps...
		if action != "map":
			print_error_exit(tag, ("TODO: figure out how to handle "
				"action {0} here!").format(action))
		simulate_unlimited_segments_outer(proc_info,
			length_left, at_addr, next_start_addr, prot_bools,
			map_bools, action)
		print_error_exit(tag, ("check that recursive call did the right "
			"thing for action={0}").format(action))
	elif layout == "overlaps_right":
		# The request starts before the existing mapping, and ends inside
		# of it. The inner method doesn't know to watch out for this case on
		# its own. Strategy: first, explicitly UNMAP the beginning portion
		# of the existing mapping by calling the inner method (which will
		# update both the vmatable and the segset in a consistent manner).
		# The later portion of the existing mapping will remain unchanged.
		# Then, we know that the request should not overlap any other
		# existing mappings (by definition of "overlaps_right"), so we
		# can pass the request directly to the inner method, where it can
		# be directly applied.
		if len(overlapped) > 1:
			print_error_exit(tag, ("number of overlapped mappings is {0}, "
				"but expect at most 1 for layout {1}!").format(
				len(overlapped), layout))
		sub_length = end_addr + 1 - mapping.start_addr
		sub_action = "unmap"
		print_debug(tag, ("[{0}, {1}]: mapping {2}, sending subrequest "
			"[{3}, {4}] with sub_action={5}").format(hex(start_addr),
			hex(end_addr), layout, hex(mapping.start_addr),
			hex(mapping.start_addr + sub_length - 1), sub_action))
		if DEBUG:
			if prot_bools:
				(prot_r, prot_w, prot_x) = prot_bools
			else:
				(prot_r, prot_w, prot_x) = (None, None, None)
			if map_bools:
				(map_s, map_anon) = map_bools
			else:
				(map_s, map_anon) = (None, None)
			if mapping.perms_key == vm.construct_perms_key2(prot_r, prot_w,
				prot_x, map_s, map_anon):
				print_warning(tag, ("Existing mapping overlaps_right with "
					"incoming request with SAME PERMISSIONS ({0}) - should "
					"these be combined into a single mapping??").format(
					mapping.perms_key))
		simulate_unlimited_segments_inner(proc_info,
			sub_length, at_addr=None, start_addr=mapping.start_addr,
			prot_bools=None, map_bools=None, action=sub_action)

		# At this point, we know that we have completely removed the part
		# of the existing mapping that overlaps. We also know that there
		# are no other mappings that overlap the current request, by the
		# definition of "overlaps_right". So, if the current request is
		# a map, protect, or remap request, send it directly to the inner
		# method, which should know how to handle it. If the current
		# request is already an unmap request, then we are done.
		if action != "unmap":
			print_debug(tag, ("[{0}, {1}]: calling inner method again on "
				"request range [{2}, {3}] with action {4}").format(
				hex(start_addr), hex(end_addr), hex(start_addr),
				hex(start_addr + length - 1), action))
			print_error_exit(tag, "check this and remove to proceed2!")
			simulate_unlimited_segments_inner(proc_info,
				length, at_addr, start_addr, prot_bools, map_bools, action)
		else:   # sanity check
			overlapped = find_vm_mappings_in_range(proc_info,
				start_addr, end_addr)
			if overlapped != []:
				print_error_exit(tag, ("after handling layout={0} for "
					"action={1}, still overlapped mappings (first: {2}) "
					"- unexpected").format(layout, action,
					overlapped[0].to_str()))

	elif layout == "within_range":
		# The incoming request entirely overlaps the existing mapping.
		# This means that whatever properties the existing mapping has,
		# they will be completely overwritten by the incoming request.
		# So, just explicitly unmap the existing mapping, then recurse
		# with the same incoming request (which may then overlap other
		# mappings that are within_range or overlaps_right).
		#
		# I manually verified that this code seems to work when there
		# are multiple "within_range" mappings that are unmapped by
		# one big request.
		sub_start_addr = mapping.start_addr
		sub_length = mapping.length
		sub_action = "unmap"
		print_debug(tag, ("[{0}, {1}]: mapping {2}, sending subrequest "
			"[{3}, {4}] with action {5}").format(hex(start_addr),
			hex(end_addr), layout, hex(sub_start_addr),
			hex(sub_start_addr + sub_length - 1), sub_action))
		simulate_unlimited_segments_inner(proc_info,
			sub_length, at_addr=None, start_addr=sub_start_addr,
			prot_bools=None, map_bools=None, action=sub_action)

		# Ok, we've removed the mapping that was entirely contained
		# within the incoming request. If the incoming request is a
		# map, remap, or protect operation, then we need to call the
		# outer method again, and it will no longer overlap the just-
		# removed mapping. If the incoming request is an unmap operation,
		# however, we only need to call the outer method again if there
		# are other overlapped mappings beyond the one that we just
		# removed; if not, then the request has been entirely handled
		# (all overlapped mappings have now been unmapped), and we can
		# return.
		if action == "unmap" and len(overlapped) == 1:
			# e.g. firefox.strace.example:14307
			print_debug(tag, ("unmapped the last overlapped mapping, "
				"so request is complete, returning now").format())
			return
		print_debug(tag, ("[{0}, {1}]: recursing for request range "
			"[{2}, {3}] with action={4}").format(hex(start_addr),
			hex(end_addr), hex(start_addr), hex(start_addr + length - 1),
			action))
		simulate_unlimited_segments_outer(proc_info,
			length, at_addr, start_addr, prot_bools, map_bools, action)
		if action != "map" and action != "unmap":
			print_error_exit(tag, ("check that recursive call did the right "
				"thing for action={0}").format(action))
	elif layout == "overlaps_range":
		# The original request range is entirely within the existing
		# mapping. In this case, we can just pass the original request
		# to the inner function - it already knows how to handle this
		# by "splitting" the existing mapping. Since the original request
		# range is entirely contained, we don't have to worry about any
		# more overlapping mappings "to the right."
		if len(overlapped) != 1:   # sanity check
			print_error_exit(tag, ("unexpected: got a mapping with "
				"layout {0}, but len(overlapped) = {1}!").format(
				layout, len(overlapped)))
		print_debug(tag, ("[{0}, {1}]: mapping {2}, so sending entire "
			"request to inner method, which should know how to split "
			"it").format(hex(start_addr), hex(end_addr), layout))
		simulate_unlimited_segments_inner(proc_info,
			length, at_addr, start_addr, prot_bools, map_bools, action)
		if (action != "protect" and action != "map" and action != "unmap"):
			# I manually verified that the inner method works here for unmaps
			# where the entire mapping is unmapped, the beginning portion of
			# a mapping is unmapped, and the ending portion of a mapping is
			# unmapped. I earlier verified and protect and map actions are
			# working as well.
			print_error_exit(tag, ("check that inner method did right thing "
				"here for action={0}").format(action))
	else:
		print_error_exit(tag, ("[{0}, {1}]: invalid layout \"{2}\" for "
			"overlapping mapping {3}").format(hex(start_addr), hex(end_addr),
			layout, mapping.to_str()))

	return

# Simulation: unlimited segments that are powers of 2.
# This is the "inner" method that ASSUMES that the incoming request
# either:
#   Does not overlap any existing mappings at all; or,
#   Matches the start-addr + length of an existing mapping exactly; or,
#   Is contained entirely within a single existing mapping.
# ...
def simulate_unlimited_segments_inner(proc_info, length, at_addr,
	start_addr, prot_bools, map_bools, action):
	tag = "simulate_unlimited_segments_inner"
	global strategy

	print_debug(tag, ("[{0}, {1}]: length={2}, at_addr={3}, prot_bools={4}, "
		"map_bools={5}, action={6}").format(hex(start_addr),
		hex(start_addr + length - 1), length, at_addr, prot_bools,
		map_bools, action))
	
	context = proc_info.get_context()
	segset = proc_info.get_segset()
	vmatable = proc_info.get_vmatable()
	stats = proc_info.get_stats()

	# length, start_addr and action are always required.
	assert length is not None
	assert start_addr is not None
	valid_actions = ["map", "remap", "protect", "unmap"]
	if action not in valid_actions:
		print_error_exit(tag, ("valid_actions are {0}, but got received "
			"action {1}").format(valid_actions, action))
	end_addr = start_addr + length - 1

	# Check and set prot_bools and map_bools stuff:
	requires_prot_bools = ["map", "protect", "remap"]
	requires_map_bools = ["map"]
	if not prot_bools:
		if action in requires_prot_bools:
			print_error_exit(tag, ("prot_bools={0} must be set for "
				"action {1}").format(prot_bools, action))
		(prot_r, prot_w, prot_x) = (None, None, None)
	else:
		if action not in requires_prot_bools:
			print_warning(tag, ("prot_bools={1} is needlessly set for "
				"action {1}").format(prot_bools, action))
		(prot_r, prot_w, prot_x) = prot_bools
	if not map_bools:
		if action in requires_map_bools:
			print_error_exit(tag, ("map_bools={0} must be set for "
				"action {1}").format(map_bools, action))
		(map_s, map_anon) = (None, None)
	else:
		if action not in requires_map_bools:
			print_warning(tag, ("map_bools={1} is needlessly set for "
				"action {1}").format(map_bools, action))
		(map_s, map_anon) = map_bools

	# Initialize segset dictionary: no restrictions on segment size,
	# so just use empty dict and add any key (segment size) to it later.
	if segset is None:
		print_warning(tag, ("I think this code is duplicated with outer "
			"method..."))
		segset = dict()
		proc_info.set_segset(segset)

	# Important: because map actions can be converted into other actions,
	# this big "switch" of action checks is not entirely if / elif / elif
	# statements; the later checks are just "if" for a reason. Also, note
	# that map should stay as the first action in this "switch"!
	#   Better way: just recursively call this function again?
	map_perms_key = None
	if action == "map":
		# First, construct the perms_key:
		map_perms_key = vm.construct_perms_key2(prot_r, prot_w, prot_x,
			map_s, map_anon)

		# Second, add entry to segment table. Make sure we're not overlapping
		# with an existing mapping first:
		test_entry = find_vm_mapping(proc_info, start_addr, starts_at=False)
		if test_entry:
			# Ugh: apparently applications can (and do) use mmap with MAP_FIXED
			# to create a mapping that overlaps an existing mapping (which
			# should be discarded); from mmap(2):
			# MAP_FIXED
			#  Don't  interpret  addr  as  a hint: place the mapping at exactly
			#  that address.  addr must be a multiple of the page size.  If the
			#  memory region specified by addr and len overlaps pages of any
			#  existing mapping(s), then the overlapped part of the existing
			#  mapping(s)  will  be discarded.  If the specified address cannot
			#  be used, mmap() will fail.  Because requiring a fixed address for
			#  a mapping is less portable, the use of this option is
			#  discouraged.
			# How should this be handled?? Convert this map action into a
			# protect action, which will be handled below.
			#   start_addr: unchanged
			#   length: unchanged
			#   perms_key: already constructed!
			if not at_addr:
				print_error_exit(tag, ("mmap produced a mapping that "
					"overlaps an existing mapping, but at_addr is not set; "
					"is this ever expected??").format())
			print_debug(tag, ("converting map action to protect!").format())
			proc_info.add_to_stats("mmap_at_addr_overlaps_existing_mapping", 1)
			action = "protect"
			
		else:
			seg_size = (strategy["to_seg_size"])(length)
			entry = vm_mapping(start_addr, length, map_perms_key, seg_size)
			vmatable[start_addr] = entry
		
			# Finally, add the segment to segset:
			try:
				(segcount, maxcount) = segset[seg_size]
				segcount += 1
				if segcount > maxcount:
					maxcount = segcount
			except KeyError:
				segcount = 1
				maxcount = 1
			segset[seg_size] = (segcount, maxcount)

	if action == "remap":
		print_error_exit(tag, ("not implemented yet: remap"))
	
	if action == "unmap" or action == "protect":
		# Re-protect and unmap look very similar to each other:
		orig_entry = find_vm_mapping(proc_info, start_addr, starts_at=False)
		if not orig_entry:
			if action == "protect":
				if start_addr < context["brk"]:
					#print_warning(tag, ("mprotect() called on a page below "
					#	"the heap brk pointer; ignoring and returning now! "
					#	"start_addr={0}, brk={1}").format(hex(start_addr),
					#	hex(context["brk"])))
					proc_info.add_to_stats("protect_below_brk", 1)
				else:
					#print_warning(tag, ("mprotect() called on a page that "
					#	"hasn't been mapped yet - converting this to a "
					#	"private anonymous map action and calling inner "
					#	"method again, then returning immediately").format())
					proc_info.add_to_stats("protect_unmapped", 1)
					new_map_bools = (False, True)   # (map_s, map_anon)
					if DEBUG:
						overlapped = find_vm_mappings_in_range(
							proc_info, start_addr, start_addr + length - 1)
						if overlapped != []:
							print_error_exit(tag, ("unexpected: mprotect "
								"being converted to anonymous map action, "
								"but there's an overlapping mapping "
								"already!").format())
					simulate_unlimited_segments_inner(proc_info,
						length, at_addr, start_addr, prot_bools,
						new_map_bools, action="map")
					return
				return
			else:   # unmap:
				# It turns out that this IS actually possible and DOES
				# actually happen :( munmap(2): "It is not an error if the
				# indicated range does not contain any mapped pages." The
				# firefox.strace.example file contains one munmap() request
				# at line 14769 which uses an address that is NEVER a part
				# of a mapping that has ever been made - I put debug
				# statements to check this inside of every vm_mapping that
				# is constructed!
				#print_warning(tag, ("action {0}: no vm_mapping found that "
				#	"even contains start_addr={1}; unfortunately this is "
				#	"actually found to happen (although it seems rare); "
				#	"just returning now.").format(action, hex(start_addr)))
				print_debug(tag, ("unmap region that has never been "
					"mapped - how common is this??").format())
				proc_info.add_to_stats("unmap_not_found", 1)

				return
		# It turns out that it's ok for an mprotect request (or map-action-
		# turned-protect-action) to extend BEYOND the end boundary of an
		# existing mapping (ugh)! So don't bother checking end-boundary
		# conditions here, just let the splitting method handle it.
		#if orig_entry.length < length:
		#	print_error_exit(tag, ("action {0}: vm_mapping's size {1} "
		#		"is less than {2} request's length {3}!?! start_addr={4}, "
		#		"orig_entry={5}").format(action,
		#		orig_entry.length, action, length, hex(start_addr),
		#		orig_entry.to_str()))
		if end_addr > orig_entry.end_addr():
			print_warning(tag, ("action '{0}': end of region to be "
				"modified [{1}, {2}] is beyond end of orig_entry {3}; "
				"make sure that split_vm_mapping() does the right "
				"thing!").format(action, hex(start_addr),
				hex(end_addr), orig_entry.to_str()))
			print_error_exit(tag, ("nevermind, want to avoid this condition"))
		if end_addr <= orig_entry.end_addr() and action == "unmap":
			# According to munmap(2): "All PAGES containing a part of the
			# indicated range are unmapped". So, we need to check for
			# incoming unmap requests that don't reach the end of a page,
			# but only when the incoming request doesn't reach the end
			# of an existing mapping (i.e. overlaps_right) - in all other
			# cases (overlaps_left, within_range, overlaps_range), there
			# is no possibility of our simulator keeping track of a piece
			# of a mapping that should have been unmapped because of this
			# whole-page requirement.
			if not vm.is_multiple_of_page_size(end_addr + 1):
				next_page_multiple = vm.next_multiple_of_page_size(end_addr)
				print_debug(tag, ("received an overlaps_right unmap request "
					"that doesn't reach end of a page: [{0}, {1}]. "
					"Extending request to end of current page: [{2}, "
					"{3}], length={4} (was {5}). orig_entry: [{6}]").format(
					hex(start_addr), hex(end_addr), hex(start_addr),
					hex(next_page_multiple - 1), next_page_multiple-start_addr,
					length, orig_entry.to_str()))
				proc_info.add_to_stats("unmap_extended_to_page_boundary", 1)
				end_addr = next_page_multiple - 1
				if end_addr > orig_entry.end_addr():
					# Don't go beyond the end of the existing mapping though.
					# All of this logic is needed because sometimes an unmap
					# request will come in that exactly matches an original
					# mmap request (that wasn't a multiple of a page size),
					# and other times an unmap request will come in that
					# doesn't reach the end of some region that was
					# mprotected beyond the end of an original mmap
					# (because mprotect() requires page-size multiples, but
					# mmap doesn't... ugh).
					end_addr = orig_entry.end_addr()
					print_debug(tag, ("extension caused unmap request "
						"to go beyond orig_entry [{0}], so now end_addr={1}, "
						"length={2}").format(
						orig_entry.to_str(), hex(end_addr),
						end_addr + 1 - start_addr))
#				if end_addr + 1 - start_addr != length:
#					print_error_exit(tag, ("check this!").format())
				length = end_addr + 1 - start_addr

		orig_perms_key = orig_entry.perms_key

		# Set up differing args for protect vs. unmap:
		if action == "protect":
			# We need to construct the new perms_key, given the new protect
			# flags. The "map" flags (private vs. shared, file-backed vs.
			# anonymous) will remain the same, so we need to get them from
			# the original orig_entry.
			# ALTERNATIVELY, if this is a map request that was converted
			# to a protect request (see above), then map_perms_key will
			# have been created already, so use this!_
			if map_perms_key is not None:
				new_perms_key = map_perms_key
			else:
				new_perms_key = vm.change_perms_key(orig_perms_key, prot_r,
					prot_w, prot_x)
			unmap = False
		else:
			new_perms_key = None
			unmap = True

		#if orig_entry.length != length:
		if not (orig_entry.length == length and
				orig_entry.start_addr == start_addr):
			# Not un-mapping or re-protecting the entire entry: first call
			# the split method, which returns an array of entries which we
			# should insert into the vmatable / segset after removing the
			# previous entry.
			remove_at = False
			new_entries = split_vm_mapping(proc_info,
				start_addr, length, unmap, strategy["to_seg_size"],
				new_perms_key)
			if not new_entries:
				print_error_exit(tag, ("split_vm_mapping() couldn't find "
					"anything to {0} at address {1}").format(action,
					hex(start_addr)))
		else:
			# No splitting needed: remove the original entry from the
			# exact starting address. If re-protecting the (entire) original
			# entry, add it to new_entries here; re-use all of the fields
			# of the original entry except for the new just-constructed
			# perms_key.
			remove_at = True
			if action == "unmap":
				new_entries = []
			elif action == "protect":
				reprotect_entry = vm_mapping(orig_entry.start_addr,
					orig_entry.length, new_perms_key, orig_entry.seg_size)
				new_entries = [reprotect_entry]
				print_debug(tag, ("exclusively for exact {0} action: created "
					"new reprotect_entry and added it to new_entries - "
					"{1}").format(action, reprotect_entry.to_str()))

		# Remove the original entry from the vmatable and segset:
		removed = remove_vm_mapping(proc_info, start_addr, starts_at=remove_at)
		if not removed:
			print_error_exit(tag, ("mapping at start_addr {0} was just "
				"found, but now can't be removed (starts_at={1})?").format(
				hex(start_addr), remove_at))
		try:
			(segcount, maxcount) = segset[removed.seg_size]
			segcount -= 1
		except KeyError:
			print_error_exit(tag, ("no segments of size {0} left in "
				"segset").format(removed.seg_size))
		segset[removed.seg_size] = (segcount, maxcount)

		# Add the new entries into the vmatable and segset if splitting
		# was required (or if re-protecting an entire entry):
		for entry in new_entries:
			try:
				test = vmatable[entry.start_addr]
				print_error_exit(tag, ("trying to add an entry, but one is "
					"already present at {0}").format(hex(entry.start_addr)))
			except KeyError:
				pass   # expected case
			vmatable[entry.start_addr] = entry

			try:
				(segcount, maxcount) = segset[entry.seg_size]
				segcount += 1
				if segcount > maxcount:
					maxcount = segcount
			except KeyError:
				segcount = 1
				maxcount = 1
			segset[entry.seg_size] = (segcount, maxcount)

	print_debug(tag, ("\nUpdated vmatable after {0}:\n{1}").format(
		action, vmatable_to_str(vmatable)))
	print_debug(tag, ("\nUpdated segset after {0}:\n{1}").format(
		action, segset_to_str(segset)))
	if vmatable_count(vmatable) != segset_count(segset):
		print_error_exit(tag, ("inconsistency: vmatable_count={0}, but "
			"segset_count()={1}").format(vmatable_count(vmatable),
			segset_count(segset)))

	return

##############################################################################
# "Handler" functions for system calls that we care about. The dictionary
# that holds pointers to these functions is further below.
def brk_handler(proc_info, key, args, retstr, linenum):
	tag = "brk_handler"

	context = proc_info.get_context()

	if (key == "sbrk"):
		print_warning(tag, "skipping sbrk() call")
		return

	match = hexnum_re.match(retstr)
	if not match:
		print_error(tag, ("unexpected retstr doesn't match hex value: "
			"{0}").format(retstr))
		return
	new_brk = int(match.group("hexnum"), 16)  # convert from hex
	context["brk"] = new_brk

	return

def clone_handler(proc_info, key, args, retstr, linenum):
	tag = "clone_handler"

	# From examining chromium-browser traces, clone() calls that create
	# a new child process look like this:
	#   clone(child_stack=0, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|
	#     SIGCHLD, child_tidptr=0x7f6babc6cc50) = 15822
	# (the value returned is the pid of the new process). clone() calls
	# that only create a new thread in the parent's address space look
	# like this:
	#   clone(child_stack=0x7f6b994fed70, flags=CLONE_VM|CLONE_FS|
	#     CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|
	#     CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID,
	#     parent_tidptr=0x7f6b994ff9d0, tls=0x7f6b994ff700,
	#     child_tidptr=0x7f6b994ff9d0) = 15843
	if "CLONE_VM" not in args:
		print_warning(tag, ("TODO: need to figure out how to handle clone "
			"calls where CLONE_VM is not set - this will create a separate "
			"memory space, just like a fork!").format())

	return

def close_handler(proc_info, key, args, retstr, linenum):
	tag = "close_handler"

	context = proc_info.get_context()

	if retstr != "0":
		print_warning(tag, ("got non-zero return value for close(), "
			"skipping: {0}").format(retstr))
		return
	
	match = posint_re.match(args)
	if not match:
		print_error_exit(tag, ("argument not a positive int: {0}").format(
			args))
	fd = int(match.group("posint"))
	#print_debug(tag, "got fd={0} from args={1}".format(fd, args))

	open_fds = context["open_fds"]
	try:
		open_fds.remove(fd)    # should be O(n)...
		context["open_fds"] = open_fds
	except ValueError:
		# whatever, for now...
		print_debug(tag, ("fd {0} not in open_fds, probably opened via "
			"pipe() or socket() or openat()...").format(fd))

	return

def dup_handler(proc_info, key, args, retstr, linenum):
	tag = "dup_handler"

	if key == "dup2":
		print_warning(tag, ("dup2 not yet supported!").format(key))
	elif key != "dup":
		print_error_exit(tag, ("key {0} not supported yet!").format(key))

	# For now, handle dup() using open() - code works exactly the same!!
	# Nevermind - for some reason, file descriptors opened with dup() don't
	# appear to be closed in the same way, or something else weird is going
	# on. In my early chromium-browser strace I see these lines, with no
	# close() calls until the last one:
	#   	dup(59)                                 = 75
	#   	write(46, "\0", 1)                      = 1
	#   	futex(0x7f8206a07508, FUTEX_WAKE_PRIVATE, 1) = 1
	#   	...
	#   	dup(56)                                 = 75
	#   	...
	#   	write(46, "\0", 1)                      = 1
	#   	poll([{fd=8, events=POLLIN}, {fd=10, events=POLLIN}, {fd=61, events=POLLIN}, {fd=62, events=POLLIN}, {fd=66, events=POLLIN}], 5, 0) = 1 ([{fd=8,   revents=POLLIN}])
	#   	read(8, "\1\0\0\0\0\0\0\0", 16)         = 8
	#   	...
	#   	open("/usr/share/icons/Humanity/mimes/16/text-x-generic.svg", O_RDONLY) = 75
	#   	fstat(75, {st_mode=S_IFREG|0644, st_size=3714, ...}) = 0
	#   	read(75, "<?xml version=\"1.0\" encoding=\"UT"..., 65536) = 3714
	#   	read(75, "", 65536)                     = 0
	#   	close(75)                               = 0
	# Anyway, let's just ignore all dup() calls for now - even though
	# we could easily grab the fd returned here, don't add it to open_fds
	# because this leads to later "open() returned an already-opened fd"
	# problems.

	return

def execve_handler(proc_info, key, args, retstr, linenum):
	tag = "execve_handler"

	progname = proc_info.get_progname()

	# first line of strace file is typically an execve - attempt to extract
	# the program name from the args here.
	#   execve("/usr/bin/firefox", ["firefox"], [/* 26 vars */]) = 0
	#   execve("/usr/bin/chromium-browser", ["chromium-browser",
	#     "https://homes.cs.washington.edu/"...], [/* 45 vars */]) = 0
	if linenum == 1:
		match = execve_args_re.match(args)
		if match:
			progname = match.group("arg1")
		else:
			print_warning(tag, ("execve_args_re failed to match on linenum "
				"{0} as expected - args are {1}").format(linenum, args))

	# execve(2) says that file descriptors remain open across execve calls,
	# so we don't have to adjust any of that context.

	proc_info.set_progname(progname)
	return

def fork_handler(proc_info, key, args, retstr, linenum):
	tag = "fork_handler"

	# Some (most?) parts of the "context" that we track will change on
	# a fork call, like file descriptors, brk pointer, etc.
	# In order to keep track of this all in a sane way, it probably makes
	# sense to strace every child process in a multi-process program
	# SEPARATELY, rather than in a single strace file, right?
	print_error_exit(tag, "Need to do anything on a fork() system call?")

	return

def madvise_handler(proc_info, key, args, retstr, linenum):
	tag = "madvise_handler"

	print_warning(tag, "not implemented yet")

	return

# See mmap(2) for details about what this method is doing.
def mmap_handler(proc_info, key, args, retstr, linenum):
	tag = "mmap_handler"
	global strategy

	context = proc_info.get_context()

	if key != "mmap":
		print_error_exit(tag, ("got non-mmap key (mmap2?): {0}").format(
			key))

	# Check for return value of -1 (MAP_FAILED) (uncommon):
	match = retstr_err_re.match(retstr)
	if match:
		print_warning(tag, ("Got failed mmap call, skipping "
		    "it: {0}").format(retstr))
		return

	match = mmap_args_re.match(args)
	if not match:
		print_error_exit(tag, ("failed args re: {0}").format(args))
	(addr, length, prot, flags, fd, offset) = match.groups()

	# To determine where the mapping is located in the virtual address space,
	# we must check the return value:
	match = hexnum_re.match(retstr)
	if not match:
		print_error_exit(tag, ("retstr {0} didn't match hexnum").format(
			retstr))
	start_addr = int(match.group("hexnum"), 16)   # convert from hex

	(at_addr_count, total_size) = context["mmap_stats"]

	# Examine all of the arguments:
	if addr != "NULL":
		at_addr_count += 1
		#print_debug(tag, ("mapping explicitly placed at addr {0}").format(
		#	addr))
		match = hexnum_re.match(addr)
		if not match:
			print_error_exit(tag, ("match failed for addr={0}").format(addr))
		at_addr = int(match.group("hexnum"), 16)   # convert from hex
		if at_addr != start_addr:
			print_warning(tag, ("at_addr {0} does not match "
				"start_addr {1} - means that OS was unable to satisfy "
				"at_addr request. Need to do anything here?").format(
				hex(at_addr), hex(start_addr)))
			proc_info.add_to_stats("at_addr_request_denied", 1)
	else:
		at_addr = None
	
	length = int(length)   # already in decimal
	total_size += length
	if length < vm.PAGE_SIZE_BYTES:
		proc_info.add_to_stats("small_mappings_explicit", 1)

	(prot_r, prot_w, prot_x) = vm.extract_prot_bools(prot)
	prot_bools = (prot_r, prot_w, prot_x)
	(map_p, map_s, map_anon, map_fixed, map_hugetlb) = vm.extract_map_bools(flags)
	map_bools = (map_s, map_anon)
	#perms_key = vm.construct_perms_key2(prot_r, prot_w, prot_x, map_s, map_anon)
	#print_debug(tag, ("constructed perms_key: {0}").format(perms_key))
	#print_debug(tag, ("args {0}:\n\tprot_r={1}, prot_w={2}, prot_x={3}, "
	#	"\n\tmap_p={4}, map_s={5}, map_anon={6}, "
	#	"map_fixed={7}\n\tmap_hugetlb={8}").format(args,
	#	prot_r, prot_w, prot_x, map_p, map_s, map_anon,
	#	map_fixed, map_hugetlb))

	if not map_anon:
		fd = int(fd)
		open_fds = context["open_fds"]
		if not sl_contains(open_fds, fd):
			print_warning(tag, ("file-backed mapping, but could not find "
			    "open fd {0} in open_fds ({1}) - fd probably came from a "
				"dup() call?").format(fd, open_fds))
			proc_info.add_to_stats("mmap_fd_not_found", 1)

	# Now that we know the mapping and its type, use a particular strategy
	# fit the mapping into some segment.
	(strategy["simulate"])(proc_info, length, at_addr,
		start_addr, prot_bools, map_bools, "map")

	context["mmap_stats"] = (at_addr_count, total_size)

	return

def mprotect_handler(proc_info, key, args, retstr, linenum):
	tag = "mprotect_handler"

	# In small firefox trace, mprotect is used to set pages to PROT_NONE
	# and PROT_READ after a larger region has been mapped as READ|WRITE.

	# Check for return value of -1:
	match = retstr_err_re.match(retstr)
	if match:
		print_warning(tag, ("Got failed mprotect call, skipping "
		    "it: {0}").format(retstr))
		return

	match = mprotect_args_re.match(args)
	if not match:
		print_error_exit(tag, ("failed args re: {0}").format(args))
	(addr, length, prot) = match.groups()
	#print_debug(tag, ("match.groups: addr={0}, length={1}, prot={2}").format(
	#	addr, length, prot))

	match2 = hexnum_re.match(addr)
	if not match2:
		print_error_exit(tag, ("match2 failed for addr={0}").format(addr))
	start_addr = int(match2.group("hexnum"), 16)   # convert from hex

	length = int(length)   # already in decimal
	(prot_r, prot_w, prot_x) = vm.extract_prot_bools(prot)
	prot_bools = (prot_r, prot_w, prot_x)

	# Simulate!
	print_debug(tag, ("simulating mprotect with start_addr={0}, length={1}, "
		"prot_bools={2}").format(hex(start_addr), length, prot_bools))
	proc_info = (strategy["simulate"])(proc_info, length, None, start_addr,
		prot_bools, None, "protect")

	return

def mremap_handler(proc_info, key, args, retstr, linenum):
	tag = "mremap_handler"

	print_error_exit(tag, "not implemented yet")

	return

def munmap_handler(proc_info, key, args, retstr, linenum):
	tag = "munmap_handler"
	global strategy

	context = proc_info.get_context()

	'''
	munmap(2):
		int munmap(void *addr, size_t length);
		On success, munmap() returns 0, on failure -1, and errno is set
		(probably to EINVAL).
	'''

	# Check for return value of -1:
	match = retstr_err_re.match(retstr)
	if match:
		print_warning(tag, ("Got failed munmap call, skipping "
		    "it: {0}").format(retstr))
		return

	match = munmap_args_re.match(args)
	if not match:
		print_error_exit(tag, ("failed args re: {0}").format(args))
	(addr, length) = match.groups()

	match2 = hexnum_re.match(addr)
	if not match2:
		print_error_exit(tag, ("match2 failed for addr={0}").format(addr))
	start_addr = int(match2.group("hexnum"), 16)   # convert from hex

	length = int(length)   # already in decimal

	# Simulate!
	proc_info = (strategy["simulate"])(proc_info, length, None, start_addr,
		None, None, "unmap")

	(at_addr_count, total_size) = context["mmap_stats"]
	total_size -= length
	context["mmap_stats"] = (at_addr_count, total_size)
	
	return

def open_handler(proc_info, key, args, retstr, linenum):
	tag = "open_handler"

	context = proc_info.get_context()

	# Check for "-1 ENOENT (No such file or directory)" or other error
	# first (pretty common):
	match = retstr_err_re.match(retstr)
	if match:
		return

	# Get the file descriptor:
	match = posint_re.match(retstr)
	if not match:
		print_error_exit(tag, ("retstr didn't match any expected REs: "
			"{0}").format(retstr))
	fd = int(match.group("posint"))
	#print_debug(tag, "got fd={0} from retstr={1}".format(fd, retstr))

	open_fds = context["open_fds"]
	if sl_contains(open_fds, fd):
		#print_error_exit(tag, ("unexpected: fd {0} already in open_fds "
		#	"{1}").format(fd, open_fds))
		print_warning(tag, ("unexpected: fd {0} already in open_fds, "
			"will just return").format(fd))
		return
	
	open_fds = sl_insert(open_fds, fd)
	context["open_fds"] = open_fds
	# Note: alternative to sorted list: built-in "heap queue" type.
	#   http://docs.python.org/3/library/heapq.html

	#if key != "open":
	#	print_debug(tag, ("open_fds: {0}").format(open_fds))
	#	print_error_exit(tag, ("added fd {0} to open_fds").format(fd))

	return

def remap_file_pages_handler(proc_info, key, args, retstr, linenum):
	tag = "remap_file_pages_handler"

	print_error_exit(tag, "not implemented yet!")

	return

def shm_handler(proc_info, key, args, retstr, linenum):
	tag = "shm_handler"

	# shmget/shmctl: looks like these should be treated like open/close - 
	#   they return file-descriptor-like things
	# shmat/shmdt: looks like these should be treated like mmap/munmap -
	#   they attach/detach shared memory regions from the process' virtual
	#   address space! However, for some reason the return address from a
	#   successful shmat call doesn't appear in the strace output...
	print_warning(tag, ("skipping shared memory command: {0}").format(key))
	proc_info.add_to_stats("shared_mem_syscalls", 1)

	return

# Dictionary of strace system calls that we care about. Keys are system call
# names, values are tuples:
#   (count, handler)
# The signature for a handler is:
#   handler(proc_info, syscall_name, args, returnstring, linenum)
# The handler for a syscall may be None if we just want to count the number
# of calls to that syscall (but note that we also keep track of this in
# "ignored_dict" right now).
syscall_dict = {
	"brk":              (0, brk_handler),
	"clone":            (0, clone_handler),
	"close":            (0, close_handler),
	"dup":              (0, dup_handler),  # open and dup handled the same!!!
	"dup2":             (0, dup_handler),
	"dup3":             (0, dup_handler),
	"execve":           (0, execve_handler),
	"fork":             (0, fork_handler),
	"madvise":          (0, madvise_handler),
	"mmap":             (0, mmap_handler),
	"mmap2":            (0, mmap_handler),
	"mprotect":         (0, mprotect_handler),
	"mremap":           (0, mremap_handler),
	"munmap":           (0, munmap_handler),
	"open":             (0, open_handler),
	"remap_file_pages": (0, remap_file_pages_handler),
	"sbrk":             (0, brk_handler),
	"shmat":            (0, shm_handler),
	"shmctl":           (0, shm_handler),
	"shmdt":            (0, shm_handler),
	"shmget":           (0, shm_handler),
	}

##############################################################################
def initialize(strace_fname, output_fname):
	tag = "initialize"

	try:
		strace_f = open(strace_fname, 'r')
	except IOError:
		print_error_exit(tag, "strace file {0} does not exist".format(
			strace_fname))
	if output_fname:
		output_f = open(output_fname, 'w')
	else:
		output_f = sys.stdout
	
	proc_tracker = processes_tracker()
	global_proc_info = process_info(0)
	global_proc_info.set_progname("GLOBAL")
	proc_tracker.insert_process_info(global_proc_info)
	
	return (strace_f, output_f, proc_tracker)

def cleanup(strace_f, output_f):
	tag = "cleanup"

	strace_f.close()
	output_f.close()
	
	return

def process_strace_file(strace_f, output_f, proc_tracker):
	tag = "process_strace_file"
	global syscall_dict

	ignored_dict = dict()

	linenum = 0
	line = strace_f.readline()
	while line:
		linenum += 1
		print_debug("", "line #:\t{0}".format(linenum))
		complete = False
		match = None       # typical syscall
		match_unf = None    # syscall unfinished
		match_res = None   # syscall resumed

		match = strace_line_re.match(line)
		if not match:
			match_unf = strace_unfinished_re.match(line)
			if not match_unf:
				match_res = strace_resumed_re.match(line)

		if match:
			pid = int((match.group("pid")).strip())
			cmd = (match.group("cmd")).strip()
			args = (match.group("args")).strip()
			retstr = (match.group("retstr")).strip()

			proc_info = proc_tracker.get_process_info(pid)
			if not proc_info:
				proc_info = process_info(pid)
				proc_tracker.insert_process_info(proc_info)

			complete = True   # further handling below
		elif match_unf:
			pid_unf = int((match_unf.group("pid")).strip())
			cmd_unf = (match_unf.group("cmd")).strip()
			args_unf = (match_unf.group("args")).strip()

			proc_info = proc_tracker.get_process_info(pid_unf)
			if not proc_info:
				proc_info = process_info(pid_unf)
				proc_tracker.insert_process_info(proc_info)

			# Unfinished system call in strace file: save cmd and args
			# for later. When resumed system call comes, make sure that
			# cmd matches, and append the resumed args to the unfinished
			# args (it looks like strace arbitrarily splits the args
			# across the unfinished lines and the resumed lines...).
			syscall_cmd = proc_info.get_syscall_cmd()
			syscall_args = proc_info.get_syscall_args()
			if syscall_cmd or syscall_args:
				print_error_exit(tag, ("pid {0}: matched unfinished "
					"syscall line, but syscall_cmd={1} or syscall_args="
					"{2} - expect both to be None!").format(pid_unf,
					syscall_cmd, syscall_args))
			proc_info.set_syscall_cmd(cmd_unf)
			proc_info.set_syscall_args(args_unf)

			print_debug(tag, ("pid {0}: unfinished syscall: saved cmd="
				"{1}, args=\"{2}\"").format(pid_unf, cmd_unf, args_unf))

		elif match_res:
			pid_res = int((match_res.group("pid")).strip())
			cmd_res = (match_res.group("cmd")).strip()
			args_res = (match_res.group("args")).strip()
			retstr_res = (match_res.group("retstr")).strip()

			proc_info = proc_tracker.get_process_info(pid_res)
			if not proc_info:
				print_error_exit(tag, ("resumed syscall, but no "
					"proc_info in proc_tracker yet! pid {0}").format(
					pid_res))
			unf_syscall_cmd = proc_info.get_syscall_cmd()
			unf_syscall_args = proc_info.get_syscall_args()
			if not unf_syscall_cmd or unf_syscall_args is None:
				print_error_exit(tag, ("pid {0}: matched resumed "
					"syscall line, but syscall_cmd={1} or syscall_args="
					"\"{2}\" - expect neither to be None!").format(pid_res,
					unf_syscall_cmd, unf_syscall_args))
			if unf_syscall_cmd != cmd_res:
				print_error_exit(tag, ("pid {0}: unfinished syscall cmd "
					"{1} doesn't match resumed syscall cmd {2}!".format(
					pid_res, unf_syscall_cmd, cmd_res)))

			if args_res != "":
				combined_args = unf_syscall_args + ", " + args_res
			else:
				combined_args = unf_syscall_args
			print_debug(tag, ("pid {0}: resumed syscall, combined_args = "
				"\"{1}\"").format(pid_res, combined_args))

			# Reset remembered cmd and args to None!
			proc_info.set_syscall_cmd(None)
			proc_info.set_syscall_args(None)

			complete = True   # further handling below
			pid = pid_res
			cmd = cmd_res
			args = combined_args
			retstr = retstr_res
		else:   # abnormal line
			global_proc_info = proc_tracker.get_process_info(0)
			if not global_proc_info:
				print_error_exit(tag, ("no global_proc_info yet!").format())
			if sigchld_line_re.match(line):
				global_proc_info.add_to_stats("SIGCHLD", 1)
			elif sigprof_line_re.match(line):
				global_proc_info.add_to_stats("SIGPROF", 1)
			elif sig_line_re.match(line):
				global_proc_info.add_to_stats("SIG other", 1)
			else:
				print_warning(tag, ("got unexpected line in strace file, will "
					"skip it:\n\t{0}").format(line))
				global_proc_info.add_to_stats("bad_strace_line", 1)

		# Must already be set: pid, proc_info, cmd, args, retstr, linenum
		if complete:
			if cmd in syscall_dict:
				val = syscall_dict[cmd]
				(count, handler) = val
				val = (count + 1, handler)
				syscall_dict[cmd] = val
				if handler:
					handler(proc_info, cmd, args, retstr, linenum)
			else:
				if cmd not in ignored_dict:
					ignored_dict[cmd] = 0
				else:
					ignored_dict[cmd] += 1

		line = strace_f.readline()
		#if linenum == 6491:   # DEBUG
		#	print_error_exit(tag, "abort")

	return

def usage():
	print('usage: {0} <strace-file> [output-file]'.format(sys.argv[0]))
	print('  strace-file: output from strace command')
	print('  output-file: optional file to write output to (otherwise stdout)')
	sys.exit(1)

def parse_args(argv):
	tag = 'parse_args'

	if len(argv) < 2 or len(argv) > 3:
		usage()
	#print_debug(tag, 'argv: {0}'.format(argv))
	strace_fname = argv[1]
	if len(argv) == 3:
		output_fname = argv[2]
	else:
		output_fname = None
	return (strace_fname, output_fname)

unlimited_strategy = {
	"simulate": simulate_unlimited_segments_outer,
	"to_seg_size": nextpowerof2,
	}
strategy = unlimited_strategy

def print_analysis(output_f, plot_fname, proc_tracker):
	tag = "print_analysis"

	print_warning(tag, ("TODO: update this method to print output to "
		"separate files for each pid?").format())

	pid_pdf = PdfPages("{0}.pdf".format(plot_fname))
	agg_segset = {}

	for proc_info in proc_tracker.get_all_process_infos():
		pid = proc_info.get_pid()
		if pid == 0:
			continue
		progname = proc_info.get_progname()
		segset = proc_info.get_segset()
		context = proc_info.get_context()
		stats = proc_info.get_stats()
		vmatable = proc_info.get_vmatable()
		output_f.write(("pid {0}: final segset:\n{1}\n").format(
			pid, segset_to_str(segset)))
		output_f.write("\n")
		output_f.write(("pid {0}: final context:\n{1}\n").format(
			pid, context_to_str(context)))
		output_f.write("\n")
		output_f.write(("pid {0}: final stats:\n{1}\n").format(
			pid, stats_to_str(stats)))
		output_f.write("\n")
		output_f.write(("pid {0}: final vmatable:\n{1}\n").format(
			pid, vmatable_to_str(vmatable)))
		output_f.write("\n")

		pid_plot_fname = "{0}-{1}".format(plot_fname, pid)
		segset_to_plot(segset, pid_plot_fname, progname, pid_pdf)
		if segset != None:
			agg_segset = segset_accumulate(agg_segset, segset)
	
	# Special for "global" proc_info:
	pid = 0
	proc_info = proc_tracker.get_process_info(pid)
	progname = proc_info.get_progname()
	context = proc_info.get_context()
	stats = proc_info.get_stats()
	segset = proc_info.get_segset()
	vmatable = proc_info.get_vmatable()
	if segset or vmatable:
		print_error_exit(tag, ("unexpected: global segset or global "
			"vmatable is not None").format())
	output_f.write(("pid {0}: final global context:\n{1}\n").format(
		pid, context_to_str(context)))
	output_f.write("\n")
	output_f.write(("pid {0}: final global stats:\n{1}\n").format(
		pid, stats_to_str(stats)))
	pid_plot_fname = "{0}-{1}".format(plot_fname, pid)
	segset_to_plot(agg_segset, pid_plot_fname, progname, pid_pdf)

	pid_pdf.close()

	return

# Main:
if __name__ == '__main__':
	tag = 'main'

	(strace_fname, output_fname) = parse_args(sys.argv)
	(strace_f, output_f, proc_tracker) = initialize(strace_fname,
		output_fname)  # opens files
	process_strace_file(strace_f, output_f, proc_tracker)
	if output_fname:
		plot_fname = "{0}-segsetplot".format(output_fname)
	else:
		plot_fname = "segsetplot"
	print_analysis(output_f, plot_fname, proc_tracker)
	cleanup(strace_f, output_f)     # closes files

	sys.exit(0)
else:
	print('Must run stand-alone')
	usage()
	sys.exit(1)

