vm-analyze
==========

This repository contains a set of scripts for automatically executing a set of Linux applications, tracing their virtual memory behavior, and analyzing + plotting the trace results.

This was my first substantial Python project, so the code may be a bit messy. Because it was developed as I learned the features and conventions of the language, in several places I have imported modules poorly, used inconsistent capitalization, have used tuples when I should have used objects, and so on; I will try to correct these things going forward.

The code in this repository currently has the following dependencies:
* Currently the [pjh/pyutils](https://github.com/pjh/pyutils) repository must be checked out in the same directory.
* To trace virtual memory activity, my patched Linux 3.9.4 kernel must be running: ...
* ...

Setup steps for my kernel:

1. cd linux-3.9.4
1. Configure...
    - Copy
    - Make oldconfig
    - Disable unnecessary features if desired...
        * (I usually just disable Paravirtualization - to make kernel build
          faster, and also because Xen build errors arose (at one point,
          not sure if they still do...) with some of my tracing changes.)
1. Build and install; I use these steps:
    make -j2 &> make.out
    sudo make headers_install
    sudo make modules_install
    sudo make install
1. Install perf tools to home directory:
    (Note: you may need these apt packages: python-dev)
    cd linux-3.9.4/tools/perf
    make
    make prefix=$HOME install
    which perf
        * (should see output: `$HOME`/bin/perf)

Setup steps for Python application / tracing scripts:
  Boot into the linux-3.9.4 kernel
  Ensure that python3 version is >= 3.3.1
    (If python3 version is lower, may need to disable timeout features
     where Popen is used)
  Set up password-less sudo:
    Ensure that /etc/sudoers has "#includedir /etc/sudoers.d" at the end
    Edit /etc/sudoers.d/pjh_passwordless_sudo:
      # man 5 sudoers
      # pjh verbena = NOPASSWD: ALL
  Edit measure/system_conf.py
  If you want to automatically run the web browser apps, install Selenium:
    ...
  Build the necessary "test programs":
    cd apps/test-programs
    Edit Makefile
      Make sure that GLIBC is set to /lib/x86_64..., and NOT to my own
      libc, unless you know what you're doing...
    make all

Setup steps for Python analysis / plotting scripts:
  Install matplotlib (and numpy?)
    Special steps to setup + build + install using python3:
      ...
  ...

To run the app / tracing scripts:
  Set applist.py to include the apps you want to run
  ./run_apps.py -h
  ./run_apps.py

