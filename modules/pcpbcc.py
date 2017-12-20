#
# Copyright (C) 2017 Marko Myllynen <myllynen@redhat.com>
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
""" PCP BCC PMDA module base class """

# pylint: disable=too-many-instance-attributes
class PCPBCCBase(object):
    """ PCP BCC Base Class """
    def __init__(self, module, config, log, err):
        """ Constructor """
        self._who = module
        self._log = log
        self._err = err

        self.bpf = None
        self.insts = {}
        self.items = []

        self.pmdaIndom = None # pylint: disable=invalid-name
        self.config = config
        self.debug = False

        for opt in self.config.options(self._who):
            if opt == 'debug':
                self.debug = self.config.getboolean(self._who, opt)

        if self.debug:
            self.log("Debug logging enabled.")

    def log(self, msg):
        """ Log a message """
        self._log(self._who + ": " + msg)

    def err(self, msg):
        """ Log an error """
        self._err(self._who + ": " + msg)

    def metrics(self):
        """ Get metric definitions """
        raise NotImplementedError

    def helpers(self, pmdaIndom): # pylint: disable=invalid-name
        """ Register helper function references """
        self.pmdaIndom = pmdaIndom

    def compile(self):
        """ Compile BPF """
        raise NotImplementedError

    def refresh(self):
        """ Refresh BPF data """
        raise NotImplementedError

    def bpfdata(self, item, inst):
        """ Return BPF data as PCP metric value """
        raise NotImplementedError

    def cleanup(self):
        """ Clean up at exit """
        if self.bpf:
            self.bpf.cleanup()
        self.bpf = None
        self.log("BPF/kprobes detached.")
