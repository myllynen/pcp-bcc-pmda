#
# Copyright (C) 2017 Marko Myllynen <myllynen@redhat.com>
# Copyright (C) 2015 Brendan Gregg
#
# BPF portion from bcc/biolatency by Brendan Gregg
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
""" PCP BCC PMDA biolatency module """

# pylint: disable=invalid-name

from ctypes import c_int
from bcc import BPF

from modules.pcpbcc import PCPBCCBase
from pcp.pmapi import pmUnits
from cpmapi import PM_TYPE_U64, PM_SEM_COUNTER, PM_TIME_USEC
from cpmapi import PM_ERR_AGAIN

#
# BPF program
#
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

typedef struct disk_key {
    char disk[DISK_NAME_LEN];
    u64 slot;
} disk_key_t;
BPF_HASH(start, struct request *);
BPF_HISTOGRAM(dist);

// time block I/O
int trace_req_start(struct pt_regs *ctx, struct request *req)
{
    u64 ts = bpf_ktime_get_ns();
    start.update(&req, &ts);
    return 0;
}

// output
int trace_req_completion(struct pt_regs *ctx, struct request *req)
{
    u64 *tsp, delta;

    // fetch timestamp and calculate delta
    tsp = start.lookup(&req);
    if (tsp == 0) {
        return 0;   // missed issue
    }
    delta = bpf_ktime_get_ns() - *tsp;
    delta /= 1000;  // usec

    // store as histogram
    dist.increment(bpf_log2l(delta));

    start.delete(&req);
    return 0;
}
"""

#
# PCP BCC PMDA constants
#
MODULE = 'biolatency'
METRIC = 'disk.all.latency'
units_usecs = pmUnits(0, 1, 0, 0, PM_TIME_USEC, 0)

#
# PCP BCC Module
#
class PCPBCCModule(PCPBCCBase):
    """ PCP BCC biolatency module """
    def __init__(self, config, log, err):
        """ Constructor """
        PCPBCCBase.__init__(self, MODULE, config, log, err)

        self.cache = {}
        self.queued = False

        for opt in self.config.options(MODULE):
            if opt == 'queued':
                self.queued = self.config.getboolean(MODULE, opt)

        if self.queued:
            self.log("Including OS queued time in I/O time.")
        else:
            self.log("Excluding OS queued time from I/O time.")

        self.log("Initialized.")

    def metrics(self):
        """ Get metric definitions """
        name = METRIC
        self.items.append(
            # Name - reserved - type - semantics - units - help
            (name, None, PM_TYPE_U64, PM_SEM_COUNTER, units_usecs, 'block io latency distribution'),
        )
        return True, self.items

    def compile(self):
        """ Compile BPF """
        self.bpf = BPF(text=bpf_text, debug=0)
        if self.queued:
            self.bpf.attach_kprobe(event="blk_start_request", fn_name="trace_req_start")
            self.bpf.attach_kprobe(event="blk_mq_start_request", fn_name="trace_req_start")
        else:
            self.bpf.attach_kprobe(event="blk_account_io_start", fn_name="trace_req_start")
        self.bpf.attach_kprobe(event="blk_account_io_completion", fn_name="trace_req_completion")
        self.log("Compiled.")

    def refresh(self):
        """ Refresh BPF data """
        dist = self.bpf.get_table("dist")

        for k, v in dist.items():
            if k.value == 0 or v.value == 0:
                continue
            low = (1 << k.value) >> 1
            high = (1 << k.value) - 1
            if low == high:
                low -= 1
            key = str(low) + "-" + str(high)
            if key not in self.cache:
                self.cache[key] = 0
            self.cache[key] += v.value
            self.insts[key] = c_int(1)

        dist.clear()

        return self.insts

    def bpfdata(self, item, inst):
        """ Return BPF data as PCP metric value """
        try:
            key = self.pmdaIndom.inst_name_lookup(inst)
            return [self.cache[key], 1]
        except: # pylint: disable=bare-except
            return [PM_ERR_AGAIN, 0]
