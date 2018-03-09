#
# Copyright (C) 2017-2018 Marko Myllynen <myllynen@redhat.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
""" PCP BCC PMDA biotop module """

# pylint: disable=invalid-name, line-too-long

from ctypes import c_int
from os import kill
from bcc import BPF

from modules.pcpbcc import PCPBCCBase
from pcp.pmapi import pmUnits
from cpmapi import PM_TYPE_U64, PM_SEM_COUNTER, PM_SPACE_BYTE
from cpmapi import PM_ERR_AGAIN

#
# BPF program
#
bpf_src = "modules/biotop.bpf"

#
# PCP BCC PMDA constants
#
MODULE = 'biotop'
METRIC = 'proc.io.perdev'
units_bytes = pmUnits(1, 0, 0, PM_SPACE_BYTE, 0, 0)

#
# PCP BCC Module
#
class PCPBCCModule(PCPBCCBase):
    """ PCP BCC biotop module """
    def __init__(self, config, log, err):
        """ Constructor """
        PCPBCCBase.__init__(self, MODULE, config, log, err)

        self.cache = {}

        self.disklookup = None
        self.update_disk_info()

        self.log("Initialized.")

    @staticmethod
    def pid_alive(pid):
        """ Test liveliness of PID """
        try:
            kill(int(pid), 0)
            return True
        except Exception: # pylint: disable=broad-except
            return False

    def update_disk_info(self):
        """ Update disk info cache """
        # cache disk major,minor -> diskname
        self.disklookup = {}
        if self.debug:
            self.log("Updating disk cache...")
        with open('/proc/diskstats') as stats:
            for line in stats:
                a = line.split()
                self.disklookup[a[0] + "," + a[1]] = a[2]

    def metrics(self):
        """ Get metric definitions """
        name = METRIC
        self.items.append(
            # Name - reserved - type - semantics - units - help
            (name, None, PM_TYPE_U64, PM_SEM_COUNTER, units_bytes, 'device io per pid'),
        )
        return True, self.items

    def compile(self):
        """ Compile BPF """
        try:
            self.bpf = BPF(src_file=bpf_src)
            self.bpf.attach_kprobe(event="blk_account_io_start", fn_name="trace_pid_start")
            self.bpf.attach_kprobe(event="blk_start_request", fn_name="trace_req_start")
            self.bpf.attach_kprobe(event="blk_mq_start_request", fn_name="trace_req_start")
            self.bpf.attach_kprobe(event="blk_account_io_completion", fn_name="trace_req_completion")
            self.log("Compiled.")
        except Exception as error: # pylint: disable=broad-except
            self.err(str(error))
            self.err("Module NOT active!")
            self.bpf = None

    def refresh(self):
        """ Refresh BPF data """
        if self.bpf is None:
            return

        counts = self.bpf.get_table("counts")

        # Clean stale data
        for key in list(self.cache):
            if not self.pid_alive(key.split("::")[1]):
                del self.cache[key]
                del self.insts[key]

        # Update current data
        for k, v in counts.items():
            disk = str(k.major) + "," + str(k.minor)

            # unnamed devices (e.g. non-device mounts)
            if k.major == 0:
                continue
            elif disk not in self.disklookup:
                # check for hot swapped devices
                self.update_disk_info()
                if disk not in self.disklookup:
                    self.log("Traced unknown device (major: {} minor: {})".format(k.major, k.minor))
                    continue

            key = self.disklookup[disk] + "::" + str(k.pid).zfill(6)
            value = v.bytes if key not in self.cache else v.bytes + self.cache[key]
            self.cache[key] = value
            self.insts[key] = c_int(1)

        counts.clear()

        return self.insts

    def bpfdata(self, item, inst):
        """ Return BPF data as PCP metric value """
        try:
            key = self.pmdaIndom.inst_name_lookup(inst).zfill(6)
            return [self.cache[key], 1]
        except Exception: # pylint: disable=broad-except
            return [PM_ERR_AGAIN, 0]
