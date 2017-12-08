#
# Copyright (C) 2017 Marko Myllynen <myllynen@redhat.com>
# Copyright (C) 2015 Brendan Gregg
#
# BPF portion from bcc/pidpersec by Brendan Gregg
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
""" PCP BCC PMDA sysfork module """

# pylint: disable=invalid-name

from ctypes import c_int
from bcc import BPF

from modules.pcpbcc import PCPBCCBase
from pcp.pmapi import pmUnits
from cpmapi import PM_TYPE_U64, PM_SEM_COUNTER, PM_COUNT_ONE
from cpmapi import PM_ERR_AGAIN

#
# BPF program
#
bpf_text = """
#include <uapi/linux/ptrace.h>

enum stat_types {
    S_COUNT = 1,
    S_MAXSTAT
};

BPF_ARRAY(stats, u64, S_MAXSTAT);

static void stats_increment(int key) {
    u64 *leaf = stats.lookup(&key);
    if (leaf) (*leaf)++;
}

void do_count(struct pt_regs *ctx) { stats_increment(S_COUNT); }
"""

#
# PCP BCC PMDA constants
#
MODULE = 'sysfork'
METRIC = 'proc.sysfork'
units_count = pmUnits(0, 0, 1, 0, 0, PM_COUNT_ONE)

#
# PCP BCC Module
#
class PCPBCCModule(PCPBCCBase):
    """ PCP BCC biotop module """
    def __init__(self, config, log, err):
        """ Constructor """
        PCPBCCBase.__init__(self, MODULE, config, log, err)

        self.value = 0

        self.log("Initialized.")

    def metrics(self):
        """ Get metric definitions """
        name = METRIC
        self.items.append(
            # Name - reserved - type - semantics - units - help
            (name, None, PM_TYPE_U64, PM_SEM_COUNTER, units_count, 'fork rate'),
        )
        return False, self.items

    def compile(self):
        """ Compile BPF """
        self.bpf = BPF(text=bpf_text, debug=0)
        self.bpf.attach_kprobe(event="sched_fork", fn_name="do_count")
        self.log("Compiled.")

    def refresh(self):
        """ Refresh BPF data """
        self.value = self.bpf["stats"][c_int(1)].value

    def bpfdata(self, item, inst):
        """ Return BPF data as PCP metric value """
        try:
            return [self.value, 1]
        except: # pylint: disable=bare-except
            return [PM_ERR_AGAIN, 0]
