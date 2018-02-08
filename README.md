# PCP BCC PMDA

[![License: Apache v2](https://img.shields.io/badge/license-Apache%20v2-brightgreen.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![License: GPLv2](https://img.shields.io/badge/license-GPLv2-brightgreen.svg)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)
[![License: GPLv3](https://img.shields.io/badge/license-GPLv3-brightgreen.svg)](https://www.gnu.org/licenses/gpl-3.0)

## Introduction

This repository contains a plugin to connect eBPF/BCC Python modules
to Performance Co-Pilot performance framework/toolkit to provide a
unified interface and advanced tools for processing BPF/BCC data.

## eBPF

From https://www.oreilly.com/ideas/ebpf-and-systems-performance:

> eBPF is a weird Linux kernel technology that powers low-overhead custom analysis tools, which can be run in production to find performance wins that no other tool can. With it, we can pull out millions of new metrics from the kernel and applications, and explore running software like never before. It’s a superpower.

## BCC

From https://github.com/iovisor/bcc:

> BCC is a toolkit for creating efficient kernel tracing and manipulation programs, and includes several useful tools and examples. It makes use of extended BPF (Berkeley Packet Filters), formally known as eBPF, a new feature that was first added to Linux 3.15. Much of what BCC uses requires Linux 4.1 and above.

> BCC makes BPF programs easier to write, with kernel instrumentation in C (and includes a C wrapper around LLVM), and front-ends in Python and lua. It is suited for many tasks, including performance analysis and network traffic control.

## PCP

> The Performance Co-Pilot (PCP, http://www.pcp.io/) system is a toolkit for collecting, archiving, and processing performance metrics from multiple operating systems. A typical Linux PCP installation offers over 1,000 metrics by default and is in turn extensible with its own plugins, or PMDAs ("Performance Metrics Domain Agents"). In addition to very complete /proc based statistics, readily available PCP PMDAs provide support for such system and application level components as 389 Directory Server, Apache, Ceph, containers, GFS2, Gluster, HAProxy, Java, libvirt, MySQL, NFS, Oracle, Postfix, PostgreSQL, Samba, and Sendmail, among others.

## Problem to Solve

While BCC has made creating new BPF programs easier and the BCC project
offers a wide variety of such tools (https://github.com/iovisor/bcc),
basically all these programs are individual, disjoint utilities that are
mostly meant for interactive use. This is not a suitable approach to
collect, monitor and analyse performance data in larger environments
where there are hundreds, if not thousands, installations and where
human intervention is infeasible at best.

While PCP offers a unified interface to a great number of performance
metrics, advanced command line utilities for analysing live or archived
metrics (e.g., http://pcp.io/man/man1/pmrep.1.html), and exporters to
external systems like
[Elasticsearch](http://pcp.io/man/man1/pcp2elasticsearch.1.html),
[Graphite](http://pcp.io/man/man1/pcp2graphite.1.html), and
[Zabbix](http://pcp.io/man/man1/pcp2zabbix.1.html), it lacks the ability
to directly connect to performance metric data sources like eBPF/BCC for
efficient kernel tracing programs.

There is a need to connect eBPF/BCC programs to a unified performance
metrics framework like PCP. There is a need to connect PCP easily to a
kernel tracing toolkit like eBPF/BCC.

## Solution

PCP BCC PMDA is a plugin which extracts live performance data from eBPF
programs by using the BCC (BPF Compiler Collection) Python frontend and
provides them to any PCP client for archiving, monitoring, exporting,
and analysis purposes. It loads and acts as a bridge for any number of
configured, separate PCP BCC PMDA Python modules running BPF programs.
Existing BCC Python tools and modules should be possible to be utilized
with PCP BCC PMDA modules with reasonable effort.

Initially, four BCC programs are available to be used by PCP, these serve
as examples how to access different data structures used by the programs:

* [pidpersec](https://github.com/iovisor/bcc/blob/master/tools/pidpersec.py)
as [sysfork.py](modules/sysfork.py)
  * Merely a simple Hello World type minimalistic example which provides
    one single metric (which in itself is not interesting as PCP already
    provides the same metric as part of its [proc metrics](http://pcp.io/man/man1/pmdaproc.1.html)
    as _kernel.all.sysfork_.
* [biolatency](https://github.com/iovisor/bcc/blob/master/tools/biolatency.py)
as [biolatency.py](modules/biolatency.py)
  * Provides block I/O latency distribution statistics.
* [biotop](https://github.com/iovisor/bcc/blob/master/tools/biotop.py)
as [biotop.py](modules/biotop.py)
  * Provides block device I/O information by process.
* [tcplife](https://github.com/iovisor/bcc/blob/master/tools/tcplife.py)
as [tcplife.py](modules/tcplife.py)
  * Provides per-process TCP statistics.

## Screenshot

With PCP BCC PMDA _biotop_ and _tcplife_ modules enabled, create a simple
[pmrep configuration file](http://pcp.io/man/man5/pmrep.conf.5.html)
for custom performance reporting, start pmrep, and run it for 50 seconds
while running _dnf -y install libreoffice_ (PID 15751) in the background
(vdb has an ext4 fs without LVM):

```Shell
# cat << EOF > pmrep.conf
[bcc-example]
timestamp = yes
interval = 5s
proc.fd.count = ,,,,
proc.io.write_bytes = ,,kB/s,,
bcc.proc.io.perdev = ,,kB/s,,
bcc.proc.io.net.tcp.rx = ,,MB,raw,
bcc.proc.io.net.tcp.tx = ,,MB,raw,
EOF
# pmrep -c ./test.conf -i '.*15751.*' --samples 10 :bcc-example
          p.f.count  p.i.write_bytes  b.p.i.perdev  b.p.i.perdev  b.p.i.n.t.rx  b.p.i.n.t.tx
          015751 /u  015751 /usr/bin   vdb::015751   vda::015751        015751        015751
              count             kB/s          kB/s          kB/s            MB            MB
10:00:04         23              N/A           N/A           N/A       166.011         0.069
10:00:09         23         2234.501      1891.713         0.000       166.011         0.069
10:00:14         23         2109.045       953.655         0.000       174.980         0.075
10:00:19         23         2137.472      1192.711         0.000       174.980         0.075
10:00:24         23         1987.648      1510.867         0.000       174.980         0.075
10:00:29         23         2099.366      1712.808         0.000       185.435         0.081
10:00:34         23         2042.308      1251.223         0.000       185.435         0.081
10:00:39         23         1708.094      1004.761         0.000       266.203         0.087
10:00:44         23         1524.975      1188.127         0.000       266.203         0.087
10:00:49         23         1823.358      1123.660         0.000       279.981         0.093
# 
```

## Upstream Status

The upstream Pull Request for BCC PMDA plugin has been merged and
available e.g. on Fedora as _pcp-pmda-bcc_ as of PCP 4.0 release.

The below installation and testing instructions are still helpful
with earlier PCP releases and on distributions with no BCC PMDA
package available.

## Installation

* Tested on latest Fedora 27 with:
  * kernel-4.14.16-300.fc27.x86_64
  * bcc-tools-0.5.0-1.fc27
  * pcp-3.12.2-1.fc27.x86_64
  * pcp-system-tools-3.12.2-1.fc27.x86_64
  * python3-pcp-3.12.2-1.fc27.x86_64
* Put SELinux into Permissive mode (for the time being):
  * setenforce 0
* Install the required packages and start the _pmcd_ daemon:
  * yum install bcc-tools pcp pcp-system-tools python3-pcp
  * systemctl enable --now pmcd
* For a PCP Quick Guide, see:
  * http://pcp.io/docs/guide.html
* Test the setup with something trivial (e.g., mimic vmstat with pmrep):
  * pmrep :vmstat
* Copy this repository as the PCP BCC PMDA directory:
  * cp -r pcp-bcc-pmda /var/lib/pcp/pmdas/bcc
* Configure and enable the plugin:
  * cd /var/lib/pcp/pmdas/bcc
  * man ./pmdabcc.1
  * vi bcc.conf
  * ./Install
* Verify operation from logs and by fetching metrics data (data may not
  be instantly available on an idle system):
  * less /var/log/pcp/pmcd/bcc.log
  * pminfo -f bcc
  * pmrep bcc.proc.sysfork
* Export and analyse:
  * pcp2{csv,json,elasticsearch,graphite,influxdb,json,xlsx,xml,zabbix}
* Enhance and extend:
  * less modules/*.bpf modules/*.py
  * vi modules/test.bpf modules/test.py bcc.conf
  * ./Remove ; ./Install ;

## Discussion / Open Items

* Security / accesss restrictions
  * Some of the modules should not be enabled without care as they may
    obviously provide sensitive information that should not be available
    for non-privileged users - see [pmcd(1)](http://pcp.io/man/man1/pmcd.1.html)
    for information on PMCD access control configuration
* Drop copy-pasted BPF programs (in PCP upstream) and import BPF code on the
  fly once the newly added _-e_ option is available on all relevant distros,
  also utilize new configuration options (like PID filter) as program args
  * https://github.com/iovisor/bcc/pull/1531
* Since PMCD uses stdout for control messages, debug output from BPF/BCC
  can't be enabled, however errors appearing on stderr will appear in
  the PMDA log
  * https://github.com/performancecopilot/pcp/issues/365
* Data could be transferred and stored in several ways, this is up to
  modules to decide which one to implement, options are at least:
  * PCP BCC PMDA modules store the data from BPF in memory
    * Current approach used by the example modules
  * Modify BPF programs to store data in readily available format
    * PCP BCC PMDA modules would not need to store no metric data
  * JSON files by using the PMDA JSON
    * Requires reading and writing files on each fetch, removal on exit
    * https://github.com/performancecopilot/pcp/issues/432
* Implement support for use separate module processes upon request (for
  example, isolate = True in module config) to allow overlapping kprobes
  * Will be added later if a real need arises, not wanted by default
* Update pcp-selinux as appropriate
  * https://github.com/performancecopilot/pcp/issues/388
* For potentially improved performance a rewrite in C could be considered
  * Would lose the ease of Python for unclear gain; not planned

## License

GPLv2+ (PCP BCC PMDA), Apache v2 (BCC/BPF programs)
