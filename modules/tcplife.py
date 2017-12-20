#
# Copyright (C) 2017 Marko Myllynen <myllynen@redhat.com>
# Copyright (C) 2016 Netflix, Inc.
#
# BPF portion from bcc/tcplife by Brendan Gregg
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

# pylint: disable=invalid-name,too-few-public-methods

from threading import Lock, Thread
import ctypes as ct
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
#define KBUILD_MODNAME "pcpbcctcplife"
#include <linux/tcp.h>
#include <net/sock.h>
#include <bcc/proto.h>

BPF_HASH(birth, struct sock *, u64);

// separate data structs for ipv4 and ipv6
struct ipv4_data_t {
    // XXX: switch some to u32's when supported
    u64 ts_us;
    u64 pid;
    u64 saddr;
    u64 daddr;
    u64 ports;
    u64 rx_b;
    u64 tx_b;
    u64 span_us;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(ipv4_events);

struct ipv6_data_t {
    u64 ts_us;
    u64 pid;
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u64 ports;
    u64 rx_b;
    u64 tx_b;
    u64 span_us;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(ipv6_events);

struct id_t {
    u32 pid;
    char task[TASK_COMM_LEN];
};
BPF_HASH(whoami, struct sock *, struct id_t);

int kprobe__tcp_set_state(struct pt_regs *ctx, struct sock *sk, int state)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u16 lport = sk->__sk_common.skc_num;
    u16 dport = sk->__sk_common.skc_dport;

    /*
     * This tool includes PID and comm context. It's best effort, and may
     * be wrong in some situations. It currently works like this:
     * - record timestamp on any state < TCP_FIN_WAIT1
     * - cache task context on:
     *       TCP_SYN_SENT: tracing from client
     *       TCP_LAST_ACK: client-closed from server
     * - do output on TCP_CLOSE:
     *       fetch task context if cached, or use current task
     */

    // capture birth time
    if (state < TCP_FIN_WAIT1) {
        /*
         * Matching just ESTABLISHED may be sufficient, provided no code-path
         * sets ESTABLISHED without a tcp_set_state() call. Until we know
         * that for sure, match all early states to increase chances a
         * timestamp is set.
         */
        u64 ts = bpf_ktime_get_ns();
        birth.update(&sk, &ts);
    }

    // record PID & comm on SYN_SENT
    if (state == TCP_SYN_SENT || state == TCP_LAST_ACK) {
        struct id_t me = {.pid = pid};
        bpf_get_current_comm(&me.task, sizeof(me.task));
        whoami.update(&sk, &me);
    }

    if (state != TCP_CLOSE)
        return 0;

    // calculate lifespan
    u64 *tsp, delta_us;
    tsp = birth.lookup(&sk);
    if (tsp == 0) {
        whoami.delete(&sk);     // may not exist
        return 0;               // missed create
    }
    delta_us = (bpf_ktime_get_ns() - *tsp) / 1000;
    birth.delete(&sk);

    // fetch possible cached data
    struct id_t *mep;
    mep = whoami.lookup(&sk);
    if (mep != 0)
        pid = mep->pid;

    // get throughput stats. see tcp_get_info().
    u64 rx_b = 0, tx_b = 0, sport = 0;
    struct tcp_sock *tp = (struct tcp_sock *)sk;
    rx_b = tp->bytes_received;
    tx_b = tp->bytes_acked;

    u16 family = sk->__sk_common.skc_family;

    if (family == AF_INET) {
        struct ipv4_data_t data4 = {.span_us = delta_us,
            .rx_b = rx_b, .tx_b = tx_b};
        data4.ts_us = bpf_ktime_get_ns() / 1000;
        data4.saddr = sk->__sk_common.skc_rcv_saddr;
        data4.daddr = sk->__sk_common.skc_daddr;
        // a workaround until data4 compiles with separate lport/dport
        data4.pid = pid;
        data4.ports = ntohs(dport) + ((0ULL + lport) << 32);
        if (mep == 0) {
            bpf_get_current_comm(&data4.task, sizeof(data4.task));
        } else {
            bpf_probe_read(&data4.task, sizeof(data4.task), (void *)mep->task);
        }
        ipv4_events.perf_submit(ctx, &data4, sizeof(data4));

    } else /* 6 */ {
        struct ipv6_data_t data6 = {.span_us = delta_us,
            .rx_b = rx_b, .tx_b = tx_b};
        data6.ts_us = bpf_ktime_get_ns() / 1000;
        bpf_probe_read(&data6.saddr, sizeof(data6.saddr),
            sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read(&data6.daddr, sizeof(data6.daddr),
            sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        // a workaround until data6 compiles with separate lport/dport
        data6.ports = ntohs(dport) + ((0ULL + lport) << 32);
        data6.pid = pid;
        if (mep == 0) {
            bpf_get_current_comm(&data6.task, sizeof(data6.task));
        } else {
            bpf_probe_read(&data6.task, sizeof(data6.task), (void *)mep->task);
        }
        ipv6_events.perf_submit(ctx, &data6, sizeof(data6));
    }

    if (mep != 0)
        whoami.delete(&sk);

    return 0;
}
"""

#
# PCP BCC PMDA constants
#
MODULE = 'tcplife'
BASENS = 'proc.io.net.tcp.'
units_bytes = pmUnits(1, 0, 0, PM_SPACE_BYTE, 0, 0)

TASK_COMM_LEN = 16      # linux/sched.h

class Data_ipv4(ct.Structure):
    """ IPv4 data struct """
    _fields_ = [
        ("ts_us", ct.c_ulonglong),
        ("pid", ct.c_ulonglong),
        ("saddr", ct.c_ulonglong),
        ("daddr", ct.c_ulonglong),
        ("ports", ct.c_ulonglong),
        ("rx_b", ct.c_ulonglong),
        ("tx_b", ct.c_ulonglong),
        ("span_us", ct.c_ulonglong),
        ("task", ct.c_char * TASK_COMM_LEN)
    ]

class Data_ipv6(ct.Structure):
    """ IPv6 data struct """
    _fields_ = [
        ("ts_us", ct.c_ulonglong),
        ("pid", ct.c_ulonglong),
        ("saddr", (ct.c_ulonglong * 2)),
        ("daddr", (ct.c_ulonglong * 2)),
        ("ports", ct.c_ulonglong),
        ("rx_b", ct.c_ulonglong),
        ("tx_b", ct.c_ulonglong),
        ("span_us", ct.c_ulonglong),
        ("task", ct.c_char * TASK_COMM_LEN)
    ]

#
# PCP BCC Module
#
class PCPBCCModule(PCPBCCBase):
    """ PCP BCC biotop module """
    def __init__(self, config, log, err):
        """ Constructor """
        PCPBCCBase.__init__(self, MODULE, config, log, err)

        self.ipv4_stats = {}
        self.ipv6_stats = {}

        self.lock = Lock()
        self.thread = Thread(name="bpfpoller", target=self.poller)
        self.thread.setDaemon(True)

        self.log("Initialized.")

    @staticmethod
    def pid_alive(pid):
        """ Test liveliness of PID """
        try:
            kill(int(pid), 0)
            return True
        except: # pylint: disable=bare-except
            return False

    def poller(self):
        """ BPF poller """
        while self.bpf:
            self.bpf.kprobe_poll()

    def handle_ipv4_event(self, _cpu, data, _size):
        """ IPv4 event handler """
        event = ct.cast(data, ct.POINTER(Data_ipv4)).contents
        pid = str(event.pid).zfill(6)
        self.lock.acquire()
        if pid not in self.ipv4_stats:
            self.ipv4_stats[pid] = [int(event.tx_b), int(event.rx_b)]
        else:
            self.ipv4_stats[pid][0] += int(event.tx_b)
            self.ipv4_stats[pid][1] += int(event.rx_b)
        self.lock.release()

    def handle_ipv6_event(self, _cpu, data, _size):
        """ IPv6 event handler """
        event = ct.cast(data, ct.POINTER(Data_ipv6)).contents
        pid = str(event.pid).zfill(6)
        self.lock.acquire()
        if pid not in self.ipv6_stats:
            self.ipv6_stats[pid] = [int(event.tx_b), int(event.rx_b)]
        else:
            self.ipv6_stats[pid][0] += int(event.tx_b)
            self.ipv6_stats[pid][1] += int(event.rx_b)
        self.lock.release()

    def metrics(self):
        """ Get metric definitions """
        name = BASENS
        self.items = (
            # Name - reserved - type - semantics - units - help
            (name + 'tx', None, PM_TYPE_U64, PM_SEM_COUNTER, units_bytes, 'tcp tx per pid'),
            (name + 'rx', None, PM_TYPE_U64, PM_SEM_COUNTER, units_bytes, 'tcp rx per pid'),
        )
        return True, self.items

    def compile(self):
        """ Compile BPF """
        try:
            self.bpf = BPF(text=bpf_text)
            self.bpf["ipv4_events"].open_perf_buffer(self.handle_ipv4_event, page_cnt=64)
            self.bpf["ipv6_events"].open_perf_buffer(self.handle_ipv6_event, page_cnt=64)
            self.thread.start()
            self.log("Compiled.")
        except Exception as error:
            self.err(str(error))
            self.err("Module NOT active!")
            self.bpf = None

    def refresh(self):
        """ Refresh BPF data """
        if self.bpf is None:
            return

        self.insts = {}

        self.lock.acquire()
        for pid in list(self.ipv4_stats):
            if not self.pid_alive(pid):
                del self.ipv4_stats[pid]
            else:
                self.insts[pid] = c_int(1)
        for pid in list(self.ipv6_stats):
            if not self.pid_alive(pid):
                del self.ipv6_stats[pid]
            else:
                self.insts[pid] = c_int(1)
        self.lock.release()

        return self.insts

    def bpfdata(self, item, inst):
        """ Return BPF data as PCP metric value """
        try:
            self.lock.acquire()
            key = self.pmdaIndom.inst_name_lookup(inst)
            value = 0
            if key in self.ipv4_stats:
                value += self.ipv4_stats[key][item]
            if key in self.ipv6_stats:
                value += self.ipv6_stats[key][item]
            self.lock.release()
            return [value, 1]
        except: # pylint: disable=bare-except
            self.lock.release()
            return [PM_ERR_AGAIN, 0]
