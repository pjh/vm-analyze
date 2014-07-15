vm-analyze
==========

This repository contains a set of scripts for tracing the virtual memory behavior of Linux applications, analyzing this trace data, and generating plots and tables that summarize the virtual memory behavior. To facilitate this analysis, this repository includes scripts for automatically executing a set of Linux applications; these automatic execution scripts may be more widely useful than the virtual memory analysis scripts.

This was my first substantial Python project, so the code may be a bit messy. Because it was developed as I learned the features and conventions of the language, in several places I have imported modules poorly, used inconsistent capitalization, used tuples when I should have used objects, used tabs instead of spaces, and so on; I will try to correct these things going forward.

Guide to source code:
* run_apps.py: main script to automatically execute the applications and capture traces of virtual memory behavior.
* generate_plots.py: main script to analyze the output from run_apps.py and generate plots and tables.
* analyze_trace.py: superseded by generate_plots.py.
* analyze/: modules used for analyzing trace data.
* app_scripts/: scripts that control the execution of each application.
* conf/: modules that control the execution of the top-level scripts.
    * applist.py: specifies which applications run_apps.py should execute.
    * PlotList.py: specifies which plots generate_plots.py should generate.
    * system_conf.py: specifies directories and other data that may differ across machines.
* plotting/: modules related to plot generation.
* trace/: modules for executing applications and capturing trace data.
* util/: various utility modules and scripts.

Before using the code in this repository, the following dependencies must be satisfied:
* The [pjh/pyutils](https://github.com/pjh/pyutils) repository must be checked out somewhere and a symlink to pyutils/pjh_utils.py must be created in the util subdirectory of this repository.
* To trace virtual memory activity, my patched Linux 3.9.4 kernel must be running: checkout the vm-analyze branch of [pjh/linux-stable](https://github.com/pjh/linux-stable/tree/vm-analyze), build it and install it. Further instructions and details are included in the README.md in that repo+branch.

So far, the code in this repository has only been run on Ubuntu 12.04 and 13.04 systems. The code is intended to be run with Python 3.3 or greater; some features that are not present in 3.2 are used.

Setup steps for Python application / tracing scripts:

1. Boot into the linux-3.9.4 kernel
1. Ensure that `python3 --version` is >= 3.3.1
    * (If python3 version is lower, may need to disable timeout features where Popen is used)
1. Set up password-less sudo: needed (for now) to control /sys/kernel/debug/tracing/... files.
    * Ensure that /etc/sudoers has "#includedir /etc/sudoers.d" at the end
    * Edit /etc/sudoers.d/pjh_passwordless_sudo:
        * # man 5 sudoers
        * # pjh verbena = NOPASSWD: ALL
1. Edit conf/system_conf.py file in this repo and ensure that the directories and other data are set for the system you're running on.
1. If you want to automatically run the web browser apps, install the Selenium python extensions:
    * ...
1. Build the necessary "test programs":
    * (TODO: add the test-programs to this repo! Then clean up these instructions.)
    * `cd apps/test-programs`
    * Edit Makefile
        * Make sure that GLIBC is set to /lib/x86_64..., and NOT to my own libc, unless you know what you're doing...
    * `make all`

Setup steps for Python analysis / plotting scripts:

1. Install matplotlib
    * Special steps to setup + build + install using python3:
        * ...

To execute the applications and trace their virtual memory behavior:

1. Set conf/applist.py to include the apps you want to run. **Important notes about plots:**
    * The Rss (physical memory) plots each consume a large amount of memory, since Rss events are much more frequent than virtual memory events. It is recommended to build these plots separately from other plots, if possible. For example, building all of the Rss plots along with the VM size plot for ten applications took 400 minutes, probably because swapping was necessary.
1. `./run_apps.py -h`
1. `./run_apps.py`

