""" The eBPF engine implementation.
"""

import os
import json
from bcc import USDT

import perun.utils as utils
import perun.collect.trace.collect_engine as engine
import perun.collect.trace.ebpf.program as program
from perun.collect.trace.watchdog import WATCH_DOG


class BpfEngine(engine.CollectEngine):
    """ The eBPF engine class, derived from the abstract CollectEngine class.

    :ivar str program: a full path to the file that stores the generated eBPF collection program
    :ivar str runtime_conf: a full path to the file that is used to configure the eBPF process
    :ivar str data: a full path to the file that stores the raw performance data
    :ivar Subprocess.Popen ebpf_process: a subprocess object of the running eBPF process
    """
    name = 'ebpf'

    def __init__(self, config):
        """ Constructs the engine object.

        :param Configuration config: the collection parameters stored in the configuration object
        """
        super().__init__(config)
        self.program = self._assemble_file_name('program', '.c')
        self.runtime_conf = self._assemble_file_name('runtime_conf', '.json')
        self.data = self._assemble_file_name('data', '.txt')
        self.ebpf_process = None
        # Create the temporary collect files
        super()._create_collect_files([self.program, self.runtime_conf, self.data])

    def check_dependencies(self):
        """ Checks the specific eBPF requirements and dependencies.

        The dependencies check is done indirectly by importing the bcc python module
        - if it exists, then the OS should already support the eBPF.
        """
        pass

    def available_usdt(self, **_):
        """ Extracts the names of the available USDT probes within the binary file.

        Inspired by: https://github.com/iovisor/bcc/blob/master/tools/tplist.py

        :return list: a list of the found USDT probe names
        """
        extractor = USDT(path=self.binary)
        usdt_probes = set()
        for probe in extractor.enumerate_probes():
            usdt_probes.add(probe.name.decode('utf-8'))
        return list(usdt_probes)

    def assemble_collect_program(self, **kwargs):
        """ Assemble the eBPF collection program.

        :param kwargs: the collection and probes configuration
        """
        program.assemble_ebpf_program(self.program, **kwargs)

    def collect(self, config, probes, **_):
        """ Run the performance data collection according to the engine capabilities.

        :param Configuration config: the collection configuration object
        :param Probes probes: the probes specification
        """
        # Create the runtime configuration file for the ebpf process with elevated privileges
        self._build_runtime_conf(config, probes)

        WATCH_DOG.info('Starting up the eBPF collection process.')
        # Run the new ebpf process with sudo privileges
        with utils.nonblocking_subprocess(
                'sudo python3 {} {}'.format(_get_ebpf_file(), self.runtime_conf), {}
        ) as ebpf_proc:
            WATCH_DOG.info('The eBPF process is running, pid {}.'.format(ebpf_proc.pid))
            self.ebpf_process = ebpf_proc
            # Wait for the process to finish
            ebpf_proc.wait()
        WATCH_DOG.info('The eBPF collection process terminated.')

    def transform(self, probes, config, **_):
        """ Transform the raw performance data to the perun profile resources.

        :param Probes probes: the probes specification
        :param Configuration config: the collection configuration

        :return iterable: a generator object that provides profile resources
        """
        WATCH_DOG.info('Transforming the raw performance data into a perun profile format')
        func_map = [{}] * len(probes.func.keys())
        # Every function probe keeps track of the current call sequence and sample value
        for func_probe in probes.func.values():
            func_map[func_probe['id']] = {
                'name': func_probe['name'],
                'sample': func_probe['sample'],
                'seq': 0
            }
        workload = config.executable.workload

        with open(self.data, 'r') as raw_data:
            for line in raw_data:
                # Partition and convert the line
                pid, func_id, call_time, amount = list(map(int, line.split()))
                # Create the profile resource
                yield {'amount': amount,
                       'uid': func_map[func_id]['name'],
                       'type': 'mixed',
                       'subtype': 'time delta',
                       'workload': workload,
                       'thread': pid,
                       'call-order': func_map[func_id]['seq'],
                       'call-time': call_time}

                # Update the sequence number
                func_map[func_id]['seq'] += func_map[func_id]['sample']

    def cleanup(self, config, **_):
        """ Safely clean up any resource that is still in use, e.g. the eBPF collection process or
        temporary collect files.

        :param Configuration config: the collection configuration
        """
        WATCH_DOG.info('Cleaning up the eBPF-related resources.')
        # Terminate the eBPF process if it is still running
        self._terminate_process('ebpf_process')

        # Zip and delete (both optional) the temporary collect files
        self._finalize_collect_files(
            ['program', 'runtime_conf', 'data'], config.keep_temps, config.zip_temps
        )

    def _build_runtime_conf(self, config, probes):
        """ Create the runtime configuration as a json-formatted file.

        :param Configuration config: the supplied collection configuration
        :param Probes probes: the probes specification
        """
        with open(self.runtime_conf, 'w') as config_handle:
            # Store the parameters that are needed by the separate eBPF process
            tracer_config = {
                'func': probes.func,
                'program_file': self.program,
                'data_file': self.data,
                'binary': config.binary,
                'command': config.executable.to_escaped_string(),
                'timeout': config.timeout
            }
            json.dump(tracer_config, config_handle, indent=2)


def _get_ebpf_file():
    """ Fetch the full path to the ebpf file that collects the performance data.

    :return str: a full path to the ebpf.py file
    """
    return os.path.join(os.path.dirname(__file__), 'ebpf.py')
