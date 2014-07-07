# Virtual memory analysis scripts.
# Developed 2012-2014 by Peter Hornyack, pjh@cs.washington.edu
# Copyright (c) 2012-2014 Peter Hornyack and University of Washington

from plotting.multiapp_plot_class import *
from util.pjh_utils import *
from plotting.plots_common import *
import trace.vm_common as vm
from collections import defaultdict

##############################################################################
# IMPORTANT: don't use any global / static variables here, otherwise
# they will be shared across plots! (and bad things like double-counting
# of vmas will happen). Only use "constants".
HIDE_RESIZES = True
TOTALKEY = 'total'
SKIP_PTES_LINKED_TO_IGNORED_VMAS = True

#SCALE = None
SCALE = GB_BYTES
  # Set SCALE to [KB,MB,GB,TB]_BYTES to use for y-axis scaling, or None
  # for no scaling.
if not SCALE:
	SCALE_LABEL = 'bytes'
else:
	SCALE_LABEL = SCALE_TO_LABEL[SCALE]

def print_debug_sizes(msg):
	if False:
		print_debug("SIZES", msg)

# Special debugging method for debugging bug in vmsize plots...
def print_debug_max(msg):
	debugthis = False
	if debugthis:
		print("VM_STATS: {}".format(msg))

class vm_size_auxdata:
	component_sizes = None
	resize_unmaps_outstanding = None
	resize_unmaps_size = None

	def __init__(self):
		self.component_sizes = defaultdict(int)
		self.resize_unmaps_outstanding = 0
		self.resize_unmaps_size = 0
	
	def reset(self):
		self.component_sizes.clear()
		self.resize_unmaps_outstanding = 0
		self.resize_unmaps_size = 0
		return

	def save_resize_unmap(self, size):
		tag = 'save_resize_unmap'
		self.resize_unmaps_outstanding += 1
		self.resize_unmaps_size -= size
		return

	def resize_remap(self, newsize):
		tag = 'resize_remap'
		if self.resize_unmaps_outstanding == 0:
			print_error(tag, ("resize_unmaps_outstanding is {}").format(
				self.resize_unmaps_outstanding))
			return

		# First, just the opposite of save_resize_unmap:
		self.resize_unmaps_outstanding -= 1
		self.resize_unmaps_size += newsize

		# Now, when the number of outstanding resizes drops back to
		# zero, return the difference in resizes (all of the unmaps
		# subtracted and the remaps added), which may be positive or
		# negative, and return it to be used to adjust the total VM
		# size. If more unmaps are outstanding (e.g. because the
		# unmap-remap pairs from multiple processes in this app's
		# trace got interleaved), then return None to signal that
		# we should wait before adjusting the VM size.
		if self.resize_unmaps_outstanding == 0:
			diff = self.resize_unmaps_size
			self.resize_unmaps_size = 0
		else:
			diff = None
		return diff

def vm_size_resetfn(auxdata):
	auxdata.reset()
	return

# Note: vma may be none! i.e. for a PageEvent with a PTE that doesn't
# have a linked vma, or an RssEvent.
def determine_basic_components(vma, separate_components):
	tag = 'determine_basic_components'

	components = [TOTALKEY]
	if separate_components and vma:
		#sharedobj = 'non-.so-file'
		#if vma and vma.filename is not None:
		#	if vma.filename == '':
		#		sharedobj = 'anon'
		#	elif '.so' in vma.filename:
		#		sharedobj = '.so-file'
		#components.append(sharedobj)
		categories = vm.classify_vma(vma)
		components += categories   #list concatenation
		print_debug(tag, ("got components from classify_vma: {}").format(
			components))

	return components

# Updates one or more component sizes kept in auxdata by adding or
# subtracting size from the current size we track. It's ok for
# size to be negative.
# For RssEvents, add_or_sub should be 'set', and size should be the
# mapping from RSS_TYPES to page counts. Otherwise, add_or_sub should
# be 'add' or 'sub', and size must be the page size being added or
# subtracted.
# Returns a list of newpoints that are created: two for each component,
# one for just the absolute size and one for the ratio...
def update_component_sizes(components, auxdata, size, add_or_sub,
		virt_or_phys, timestamp, do_ratio, do_difference=False):
	tag = 'update_component_sizes'

	#print_debug(tag, ("entered: add_or_sub={}, virt_or_phys={}, "
	#	"components={}, do_difference={}").format(add_or_sub, virt_or_phys,
	#	components, do_difference))

	newpoints = []
	for component in components:
		if component != TOTALKEY:
			vp_component = "{}-{}".format(component, virt_or_phys)
		else:
			vp_component = "{}".format(virt_or_phys)

		# component_sizes is a defaultdict, so if a vp_component key
		# has not been encountered yet, its entry will be initialized
		# to 0 and then size will be added / subtracted.
		if add_or_sub == 'add':
			print_debug_sizes(("adding size {} to component_sizes["
				"{}]={}").format(size, vp_component,
				auxdata.component_sizes[vp_component]))
			auxdata.component_sizes[vp_component] += size
		elif add_or_sub == 'sub':
			print_debug_sizes(("subtracting size {} from component_sizes["
				"{}]={}").format(size, vp_component,
				auxdata.component_sizes[vp_component]))
			auxdata.component_sizes[vp_component] -= size
		elif add_or_sub == 'set':
			# This path added later for RssEvents:
			if component == TOTALKEY:
				# For now, we don't include swap in "total physical
				# memory size."
				rss_count = size['MM_FILEPAGES'] + size['MM_ANONPAGES']
			elif component == vm.file_label:
				rss_count = size['MM_FILEPAGES']
			elif component == vm.anon_label:
				rss_count = size['MM_ANONPAGES']
			elif component == vm.swap_label:
				rss_count = size['MM_SWAPENTS']
			else:
				print_unexpected(True, tag, ("unexpected component {} "
					"for add_or_sub={} (RssEvent)").format(
					component, add_or_sub))
			rss_size = rss_count * vm.PAGE_SIZE_BYTES
			auxdata.component_sizes[vp_component] = rss_size
			print_debug_sizes(tag, ("set component_sizes[{}] = {} [{}] "
				"from RssEvent").format(vp_component, rss_size,
				pretty_bytes(rss_size)))
		else:
			print_unexpected(True, tag, ("invalid add_or_sub="
				"{}").format(add_or_sub))
			return []

		# Track maximum for each component as well (but for now, just print
		# it out; there's not a great way to access it later...)
		nowsize = auxdata.component_sizes[vp_component]
		max_component = "{}-max".format(vp_component)
		try:
			maxsize = auxdata.component_sizes[max_component]
		except KeyError:
			maxsize = -1
		if nowsize > maxsize:
			auxdata.component_sizes[max_component] = nowsize
			print_debug(tag, ("new max: {}: {}: {}").format(timestamp,
				max_component, pretty_bytes(nowsize)))

		print_debug_sizes(("component_sizes[{}] = {}").format(
			vp_component, auxdata.component_sizes[vp_component]))
		debug_vmsize(tag, ("component_sizes[{}] = {}").format(
			vp_component, auxdata.component_sizes[vp_component]))
		if auxdata.component_sizes[vp_component] < 0:
			print_error_exit(tag, ("component_sizes[{}] hit {}; "
				"timestamp is {}. component_sizes={}").format(
				vp_component, auxdata.component_sizes[vp_component],
				timestamp, auxdata.component_sizes))

		# debugging:
		if False and vp_component == 'total-virt':
			debug_vmsize(tag, ("total_vm_size={}").format(
				pretty_bytes(auxdata.component_sizes[vp_component])))
			maxcomp = 'total-virt-max'
			debug_max_vm_size = True
			if debug_max_vm_size:
				# I verified that the total-virt-max tracked here
				# matches the max_vm_size and max_vm_size_time tracked
				# in the process_info object.
				try:
					maxvirt = auxdata.component_sizes[maxcomp]
					if auxdata.component_sizes[vp_component] > maxvirt:
						auxdata.component_sizes[maxcomp] = (
								auxdata.component_sizes[vp_component])
						print_debug_max(("{}: max={}").format(timestamp,
							pretty_bytes(auxdata.component_sizes[maxcomp])))
				except KeyError:
					auxdata.component_sizes[maxcomp] = (
							auxdata.component_sizes[vp_component])

		if do_ratio or do_difference:
			# One point for the ratio:
			point = update_ratios(auxdata, component, timestamp,
					do_difference)
			newpoints.append(point)
		else:
			# One point for the standard component:
			point = datapoint()
			point.timestamp = timestamp
			point.count = auxdata.component_sizes[vp_component]
			point.component = vp_component
			newpoints.append(point)

	debug_vmsize(tag, '')
	return newpoints

# If this vma represents a real vma alloc or free, then this
# method updates the vm size maintained in auxdata and returns a
# point with timestamp and count fields set. If this vma does not
# actually represent a new alloc or free, then None is returned.
def update_vm_size(vma, auxdata, do_ratio, separate_components,
		do_difference=False):
	tag = 'update_vm_size'

	#debug_vmsize(tag, None, ("total_vm_size    - got vma {}").format(
	#	vma))

	# Skip this vma if it's for a shared lib, guard region, etc.
	# See more detailed comments in vmacount_datafn().
	if vm.ignore_vma(vma):
		debug_ignored(tag, ("ignoring vma {}").format(vma))
		return []

	# At the very least, components will contain ['total'].
	components = determine_basic_components(vma, separate_components)

	# See extensive comments in consume_plot_event() about how each
	# operation is encoded, especially frees.
	# 
	# IMPORTANT: when tracking vma SIZE (and not just counts), we
	# also need to consider resize events!
	#   The HIDE_RESIZE constant controls whether or not we completely
	#   remove the vma's size on the unmap and add the new size back
	#   on the remap (HIDE_RESIZE = False), or if we make the plots
	#   looks smoother by keeping track of the unmap-remap pair and
	#   only adding/subtracting the difference in size (HIDE_RESIZE =
	#   True).
	# handle_plot_event() should ensure that we never get
	# a resize-remap without getting a resize-unmap first
	# (unless we happen to have started our kernel trace
	# right in the middle of an unmap-remap pair, which is
	# extremely unlikely, and even if this happens it
	# will be noticed in the analysis script already I
	# think).
	#   Does it matter that the unmap-remap pairs for multiple
	#   processes may be fed into the same plot? Possibly; if
	#   it turns out that this sort of interleaving does happen
	#   in some traces, then it's non-trivial to solve here
	#   because the tgid passed to the datafn is the same (the
	#   "tgid_for_stats") for all of the processes, so we can't
	#   separate out the context in that way. Presumably we could
	#   keep a running "deficit" of unmapped sizes, and only
	#   generate new points on the plot when the number of
	#   outstanding unmaps is actually 0. I should probably just
	#   implement this now, before I run into this case in a
	#   real trace...
	# Note: similar logic is used here for both vmacount_datafn() and
	# update_vm_size() - if you change one, examine the other one too.
	if ((vma.vma_op == 'alloc' or vma.vma_op == 'access_change') and
		not vma.is_unmapped):
		# Very first allocation of this vma, OR a remap for an
		# access_change, which could result in a previously-ignored
		# vma now being not-ignored (see vmacount_datafn()).
		#print_debug_sizes(("vma alloc, filename={}, size={}").format(
		#	vma.filename, vma.length))
		newpoints = update_component_sizes(components, auxdata,
				vma.length, 'add', vm.VIRT_LABEL, vma.timestamp,
				do_ratio, do_difference)
	elif vma.vma_op == 'resize' and not vma.is_unmapped:
		if HIDE_RESIZES:
			size = auxdata.resize_remap(vma.length)
			print_debug(tag, ("resize unmap-remap pair: resized "
				"length is {}, adding diff {} to component "
				"sizes").format(vma.length, size))
		else:
			size = vma.length

		# resize_remap() may return None if there are still outstanding
		# unmaps.
		if size is not None:
			# update_component_sizes() should work ok even if size
			# is negative with 'add'.
			newpoints = update_component_sizes(components, auxdata,
					size, 'add', vm.VIRT_LABEL, vma.timestamp,
					do_ratio, do_difference)
		else:
			newpoints = []

	elif vma.is_unmapped and vma.unmap_op == 'resize':
		if HIDE_RESIZES:
			# When we get a resize-unmap, save the unmapped vma's size
			# in auxdata, but don't update any tracked sizes or generate
			# any new points yet.
			auxdata.save_resize_unmap(vma.length)
			print_debug(tag, ("resize unmap: saved unmapped vma length "
				"{}").format(vma.length))
			newpoints = []
		else:
			# Same as unmapped-free case below.
			newpoints = update_component_sizes(components, auxdata,
					vma.length, 'sub', vm.VIRT_LABEL, vma.unmap_timestamp,
					do_ratio, do_difference)
	elif (vma.is_unmapped and
		  (vma.unmap_op == 'free' or vma.unmap_op == 'access_change')):
		# Explicit free of this vma (no matter the operation that
		# allocated it (most recently operated on it)), OR an
		# unmap operation for an access_change, which could be
		# changing the permissions on a vma to something that we
		# want to ignore, so we need to un-count the vma's size here
		# first! (see vmacount_datafn() too).
		#print_debug_sizes(("vma free, filename={}, size={}").format(
		#	vma.filename, vma.length))
		newpoints = update_component_sizes(components, auxdata,
				vma.length, 'sub', vm.VIRT_LABEL, vma.unmap_timestamp,
				do_ratio, do_difference)
	else:
		newpoints = []

	return newpoints

def update_phys_size(page_event, auxdata, do_ratio, separate_components):
	tag = 'update_phys_size'

	if SKIP_PTES_LINKED_TO_IGNORED_VMAS:
		# For calculating VM size, we're skipping vmas that represent
		# shared libs, guard regions, etc. (in update_vm_size()). So,
		# seems like we have to skip PTE events linked to those VMAs too.
		# Looking at the plots output for dedup before and after adding
		# this check, this makes no difference in the plot appearance; only
		# 306 ptes were ignored here. Perhaps more of a difference would
		# be made for e.g. firefox or office.
		if page_event.pte.vma and vm.ignore_vma(page_event.pte.vma):
			debug_ignored(tag, ("ignoring pte linked to vma {}").format(
				page_event.pte.vma))
			return []

	# At the very least, components will contain ['total'].
	components = determine_basic_components(page_event.pte.vma,
			separate_components)
	
	if page_event.pte.vma:
		filename = page_event.pte.vma.filename
	else:
		filename = "no-linked-vma"

	# See extensive comments in consume_vma() about how each operation
	# is encoded, especially frees!
	if page_event.unmap:
		print_debug_sizes(("page unmap, filename={}, size={}").format(
			filename, page_event.pte.pagesize))
		newpoints = update_component_sizes(components, auxdata,
				page_event.pte.pagesize, 'sub', vm.PHYS_LABEL,
				page_event.timestamp, do_ratio)
	else:
		print_debug_sizes(("page map, filename={}, size={}").format(
			filename, page_event.pte.pagesize))
		newpoints = update_component_sizes(components, auxdata,
				page_event.pte.pagesize, 'add', vm.PHYS_LABEL,
				page_event.timestamp, do_ratio)

	return newpoints

def update_rss_size(rss_event, auxdata, do_ratio, separate_components,
		do_difference):
	tag = 'update_rss_size'

	components = [TOTALKEY]
	if separate_components:
		components += [vm.file_label, vm.anon_label, vm.swap_label]

	newpoints = update_component_sizes(components, auxdata,
		rss_event.rss_pages, 'set', vm.PHYS_LABEL, rss_event.timestamp,
		do_ratio, do_difference)
	return newpoints

# If this page_event represents a real page alloc or free, then this method
# updates the physical memory size maintained in auxdata and returns
# a point with timestamp and count fields set. If this page_event does not
# actually represent a new alloc or free, then None is returned (currently
# this never happens, but at some point it may if page_events are made
# more complex).
def update_phys_size_old(page_event, auxdata, components, separate_components):
	tag = 'update_phys_size_old'

	if page_event.unmap:
		auxdata.current_phys_size -= page_event.pte.pagesize
		print_debug(tag, ("unmapped pfn {} and decremented physical "
			"memory size by its pagesize {}; phys. mem size is now "
			"{}").format(page_event.pte.pfn, page_event.pte.pagesize,
			pretty_bytes(auxdata.current_phys_size)))
	else:
		auxdata.current_phys_size += page_event.pte.pagesize
		print_debug(tag, ("mapped pfn {} and incremented physical "
			"memory size by its pagesize {}; phys. mem size is now "
			"{}").format(page_event.pte.pfn, page_event.pte.pagesize,
			pretty_bytes(auxdata.current_phys_size)))

	point = datapoint()
	point.timestamp = page_event.timestamp
	point.count = auxdata.current_phys_size

	return point

def update_ratios(auxdata, component, timestamp, do_difference):
	tag = 'update_ratios'

	if component == TOTALKEY:
		virt_component  = "{}".format(vm.VIRT_LABEL)
		phys_component  = "{}".format(vm.PHYS_LABEL)
		ratio_component = "{}".format(vm.RATIO_LABEL)
		diff_component  = "{}".format(vm.DIFFERENCE_LABEL)
	else:		
		virt_component  = "{}-{}".format(component, vm.VIRT_LABEL)
		phys_component  = "{}-{}".format(component, vm.PHYS_LABEL)
		ratio_component = "{}-{}".format(component, vm.RATIO_LABEL)
		diff_component  = "{}-{}".format(component, vm.DIFFERENCE_LABEL)
	ratio_max = "{}-max".format(ratio_component)
	diff_max  = "{}-max".format(diff_component)

	try:
		virt_size = auxdata.component_sizes[virt_component]
	except KeyError:
		virt_size = 0.0
	try:
		phys_size = auxdata.component_sizes[phys_component]
	except KeyError:
		phys_size = 0.0

	point = datapoint()
	point.timestamp = timestamp

	if do_difference:
		diff_size = float(virt_size) - float(phys_size)
		if diff_size < 0.0:
			print_unexpected(False, tag, ("calculated negative "
				"difference between virt_size={} and phys_size={}: "
				"{} ({})").format(pretty_bytes(virt_size),
				pretty_bytes(phys_size), pretty_bytes(diff_size),
				diff_size))
			diff_size = 0.0
		#print_debug(tag, ("do_difference: virt_size={}, phys_size={}, "
		#	"diff_size={}").format(pretty_bytes(virt_size),
		#	pretty_bytes(phys_size), pretty_bytes(diff_size)))
		try:
			maxdiff = auxdata.component_sizes[diff_max]
		except KeyError:
			maxdiff = -0.1
		if diff_size > maxdiff:
			auxdata.component_sizes[diff_max] = diff_size
			#print_debug(tag, ("new max diff size: {}: {}: {}").format(
			#	timestamp, maxdiff, diff_size))
		point.count = diff_size
		point.component = diff_component
	else:
		if virt_size != 0.0:  # is == 0 comparison ok for floats in python?
			nowratio = (phys_size / virt_size)
			if nowratio > 1.0:
				# Do we still expect this to happen now that we're using
				# rss events instead of pte events for tracking resident
				# physical pages? Unfortunately, yes - even (especially?
				# in hello-world, there are 400ish events that cause us
				# to calculate a ratio greater than 1 here. Half of these
				# happen at the beginning of the trace, when there is
				# exactly one virtual page accounted for but many physical
				# pages.....
				print_unexpected(False, tag, ("calculated ratio {} > 1.0 - "
					"phys_size={}, virt_size={}").format(nowratio, phys_size,
					virt_size))
				nowratio = 1.0
		else:
			nowratio = 0.0
		#print_debug(tag, ("do_ratio: virt_size={}, phys_size={}, "
		#	"nowratio={}").format(pretty_bytes(virt_size),
		#	pretty_bytes(phys_size), nowratio))

		try:
			maxratio = auxdata.component_sizes[ratio_max]
		except KeyError:
			maxratio = -0.1
		if nowratio > maxratio:
			auxdata.component_sizes[ratio_max] = nowratio
			#print_debug(tag, ("new max: {}: {}: {}").format(timestamp,
			#	ratio_max, nowratio))
		point.count = nowratio
		point.component = ratio_component
	
	return point

##############################################################################

# This method is very similar to vmacount_datafn - if you modify one,
# you may want to modify the other.
# Note: currentapp may be None, e.g. for checkpoints!
def size_datafn(auxdata, plot_event, tgid, currentapp, do_ratio,
		separate_components, just_virt, do_difference=False):
	tag = 'size_datafn'

	# This method handles plot_events with *either* vma or page_event
	# set - however, both should not be set at the same time!
	if (plot_event.vma and
		(plot_event.page_event or plot_event.rss_event)):
		print_warning(tag, ("got a plot_event with both vma and "
			"page_event or rss_event set - not handled by this datafn, "
			"is this expected by ANY datafn?").format())
		return None

	if plot_event.vma:
		newpoints = update_vm_size(plot_event.vma, auxdata,
			do_ratio, separate_components, do_difference)
	elif not just_virt and plot_event.page_event:
		newpoints = update_phys_size(plot_event.page_event, auxdata,
			do_ratio, separate_components)
	elif not just_virt and plot_event.rss_event:
		newpoints = update_rss_size(plot_event.rss_event, auxdata,
			do_ratio, separate_components, do_difference)
	elif plot_event.cp_event:
		point = new_cp_datapoint(plot_event)
		seriesname = "{}".format(CP_SERIESNAME)
		return [(seriesname, point)]
	else:
		# We don't care about this plot_event.
		return None

	# update_vm_size() and update_phys_size() will return an empty
	# newpoints list if the event didn't represent an actual
	# virtual/physical allocation or free. In each of these datapoints
	# we stored the component, which we use (along with the appname) 
	# to construct the seriesname for the list of tuples that we return
	# here.
	if len(newpoints) > 0:
		returnlist = []
		for p in newpoints:
			# In order to get colors right, set seriesname to just the
			# appname for the "main" or "only" line in the plot:
			if (just_virt or p.component == vm.RATIO_LABEL
				or p.component == vm.DIFFERENCE_LABEL):
				seriesname = "{}".format(currentapp)
			else:
				seriesname = "{}-{}".format(currentapp, p.component)
			p.appname = currentapp
			returnlist.append((seriesname, p))
		return returnlist

	return None

def vm_size_datafn(auxdata, plot_event, tgid, currentapp):
	return size_datafn(auxdata, plot_event, tgid, currentapp,
			do_ratio=False, separate_components=False,
			just_virt=True)

def virt_phys_size_datafn(auxdata, plot_event, tgid, currentapp):
	return size_datafn(auxdata, plot_event, tgid, currentapp,
			do_ratio=False, separate_components=False,
			just_virt=False)

def virt_phys_diff_datafn(auxdata, plot_event, tgid, currentapp):
	return size_datafn(auxdata, plot_event, tgid, currentapp,
			do_ratio=False, separate_components=False,
			just_virt=False, do_difference=True)

def virt_phys_ratio_datafn(auxdata, plot_event, tgid, currentapp):
	return size_datafn(auxdata, plot_event, tgid, currentapp,
			do_ratio=True, separate_components=False,
			just_virt=False)

def virt_phys_size_component_datafn(auxdata, plot_event, tgid, currentapp):
	return size_datafn(auxdata, plot_event, tgid, currentapp,
			do_ratio=False, separate_components=True,
			just_virt=False)

def virt_phys_ratio_component_datafn(auxdata, plot_event, tgid, currentapp):
	return size_datafn(auxdata, plot_event, tgid, currentapp,
			do_ratio=True, separate_components=True,
			just_virt=False)

##############################################################################

def vm_size_ts_plotfn(seriesdict, plotname, workingdir):
	tag = 'vm_size_ts_plotfn'

	#ysplits = None
	ysplits = [0.5, 5]

	title = 'Total VM size over time'
	yaxis = "Total size of mapped virtual address space ({})".format(
			SCALE_LABEL)

	return size_ts_plotfn(seriesdict, plotname, title, yaxis, ysplits)

def virt_phys_size_ts_plotfn(seriesdict, plotname, workingdir):
	tag = 'virt_phys_size_ts_plotfn'

	ysplits = None
	#ysplits = [1, 5, 10]

	title = 'Total virtual memory and resident physical memory'
	yaxis = "Total size ({})".format(SCALE_LABEL)

	return size_ts_plotfn(seriesdict, plotname, title, yaxis, ysplits)

def virt_phys_diff_ts_plotfn(seriesdict, plotname, workingdir):
	tag = 'virt_phys_diff_ts_plotfn'

	ysplits = None
	#ysplits = [1, 5, 10]

	#title = ('Difference between allocated virtual memory and '
	#	'resident physical memory')
	title = ('Amount of non-resident virtual memory')
	yaxis = "Size ({})".format(SCALE_LABEL)

	return size_ts_plotfn(seriesdict, plotname, title, yaxis, ysplits)

def size_ts_plotfn(seriesdict, plotname, title, yaxis, ysplits):
	tag = 'size_ts_plotfn'

	# More detailed comments are in vm_ratio_ts_plotfn().

	for appserieslist in seriesdict.values():
		normalize_appserieslist(appserieslist, True)
	cp_series = handle_cp_series(seriesdict)
	plotdict = construct_scale_ts_plotdict(seriesdict, scale=SCALE)

	xaxis = "Execution time"
	return plot_time_series(plotdict, title, xaxis, yaxis, ysplits,
			logscale=False, cp_series=cp_series)

def vm_ratio_ts_plotfn(seriesdict, plotname, workingdir):
	tag = 'vm_ratio_ts_plotfn'

	# seriesdict maps app names to lists of series for that app. This
	# is convenient because we want to normalize all of the series
	# for an app to each other. One (or more?) of the series for an
	# app may contain checkpoint data rather than typical series
	# data - this doesn't concern us here though, we want to normalize
	# the checkpoints for this app as well.
	# Because normalize_appserieslist() normalizes every app's series
	# to the range [0..1], normalizing every app's series also serves
	# to normalize every app to every other app, so after this point
	# no additional normalization should be necessary... I think.
	for appserieslist in seriesdict.values():
		normalize_appserieslist(appserieslist, True)
	
	# Now, the timeseries plot method wants a dict that maps seriesnames
	# to series. First, remove any checkpoint series that are kept
	# in the seriesdict:
	cp_series = handle_cp_series(seriesdict)

	# Now, iterate over all of the serieslists in the seriesdict
	# and insert them into a new plotdict.
	plotdict = construct_scale_ts_plotdict(seriesdict)

	ysplits = None
	title = ("Ratio of resident to virtual memory").format()
	xaxis = "Execution time"
	yaxis = "Ratio"
	return plot_time_series(plotdict, title, xaxis, yaxis, ysplits,
			logscale=False, yax_units='percents', cp_series=cp_series)

vm_size_ts_plot = multiapp_plot('vm-size-ts', vm_size_auxdata,
		vm_size_ts_plotfn, vm_size_datafn, vm_size_resetfn)

# Newer rss-event-based plots:
virt_phys_size_ts_plot = multiapp_plot('virt-phys-size', vm_size_auxdata,
		virt_phys_size_ts_plotfn, virt_phys_size_datafn, vm_size_resetfn)
virt_phys_ratio_ts_plot = multiapp_plot('virt-phys-ratio', vm_size_auxdata,
		vm_ratio_ts_plotfn, virt_phys_ratio_datafn, vm_size_resetfn)
virt_phys_diff_ts_plot = multiapp_plot('virt-phys-diff', vm_size_auxdata,
		virt_phys_diff_ts_plotfn, virt_phys_diff_datafn, vm_size_resetfn)

# Older PTE-event-based plots:
virt_pte_size_ts_plot = multiapp_plot('virt-phys-size-pte', vm_size_auxdata,
		virt_phys_size_ts_plotfn, virt_phys_size_datafn, vm_size_resetfn)
virt_pte_ratio_ts_plot = multiapp_plot('virt-phys-ratio-pte', vm_size_auxdata,
		vm_ratio_ts_plotfn, virt_phys_ratio_datafn, vm_size_resetfn)

virt_phys_size_component_ts_plot = multiapp_plot(
		'virt-phys-size-component', vm_size_auxdata,
		virt_phys_size_ts_plotfn, virt_phys_size_component_datafn,
		vm_size_resetfn)
virt_phys_ratio_component_ts_plot = multiapp_plot(
		'virt-phys-ratio-component', vm_size_auxdata,
		vm_ratio_ts_plotfn, virt_phys_ratio_component_datafn,
		vm_size_resetfn)

if __name__ == '__main__':
	print_error_exit("not an executable module")
