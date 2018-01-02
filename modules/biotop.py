#
# Copyright (C) 2017 Marko Myllynen <myllynen@redhat.com>
# Copyright (C) 2016 Netflix, Inc.
#
# BPF portion from bcc/biotop by Brendan Gregg
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
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

// for saving process info by request
struct who_t {
    u32 pid;
    char name[TASK_COMM_LEN];
};

// the key for the output summary
struct info_t {
    u32 pid;
    int rwflag;
    int major;
    int minor;
    char name[TASK_COMM_LEN];
};

// the value of the output summary
struct val_t {
    u64 bytes;
    u64 us;
    u32 io;
};

BPF_HASH(start, struct request *);
BPF_HASH(whobyreq, struct request *, struct who_t);
BPF_HASH(counts, struct info_t, struct val_t);

// cache PID and comm by-req
int trace_pid_start(struct pt_regs *ctx, struct request *req)
{
    struct who_t who = {};

    if (bpf_get_current_comm(&who.name, sizeof(who.name)) == 0) {
        who.pid = bpf_get_current_pid_tgid();
        whobyreq.update(&req, &who);
    }

    return 0;
}

// time block I/O
int trace_req_start(struct pt_regs *ctx, struct request *req)
{
    u64 ts;

    ts = bpf_ktime_get_ns();
    start.update(&req, &ts);

    return 0;
}

// output
int trace_req_completion(struct pt_regs *ctx, struct request *req)
{
    u64 *tsp;

    // fetch timestamp and calculate delta
    tsp = start.lookup(&req);
    if (tsp == 0) {
        return 0;    // missed tracing issue
    }

    struct who_t *whop;
    struct val_t *valp, zero = {};
    u64 delta_us = (bpf_ktime_get_ns() - *tsp) / 1000;

    // setup info_t key
    struct info_t info = {};
    info.major = req->rq_disk->major;
    info.minor = req->rq_disk->first_minor;
/*
 * The following deals with a kernel version change (in mainline 4.7, although
 * it may be backported to earlier kernels) with how block request write flags
 * are tested. We handle both pre- and post-change versions here. Please avoid
 * kernel version tests like this as much as possible: they inflate the code,
 * test, and maintenance burden.
 */
#ifdef REQ_WRITE
    info.rwflag = !!(req->cmd_flags & REQ_WRITE);
#elif defined(REQ_OP_SHIFT)
    info.rwflag = !!((req->cmd_flags >> REQ_OP_SHIFT) == REQ_OP_WRITE);
#else
    info.rwflag = !!((req->cmd_flags & REQ_OP_MASK) == REQ_OP_WRITE);
#endif

    whop = whobyreq.lookup(&req);
    if (whop == 0) {
        // missed pid who, save stats as pid 0
        valp = counts.lookup_or_init(&info, &zero);
    } else {
        info.pid = whop->pid;
        __builtin_memcpy(&info.name, whop->name, sizeof(info.name));
        valp = counts.lookup_or_init(&info, &zero);
    }

    // save stats
    valp->us += delta_us;
    valp->bytes += req->__data_len;
    valp->io++;

    start.delete(&req);
    whobyreq.delete(&req);

    return 0;
}
"""

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
            self.bpf = BPF(text=bpf_text)
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
            if disk not in self.disklookup:
                self.update_disk_info()
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
