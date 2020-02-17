""" The eBPF collection process that has to be invoked with elevated sudo privileges in order to
attach the selected probes.
"""

import json
import sys
import time

from bcc import BPF, PerfType, PerfHWConfig

import perun.utils as utils
from perun.collect.trace.threads import TimeoutThread


class BpfContext:
    """ A BPF context class that stores the reference to the BPF instance, output data file and
    runtime configuration.

    :ivar dict config: the runtime configuration
    :ivar TextIO data: the raw performance data file
    :ivar BPF bpf: the BPF instance
    """
    def __init__(self, runtime_config):
        # Load the runtime configuration
        with open(runtime_config, 'r') as config_handle:
            self.config = json.load(config_handle)
        # Open the data file for continuous write
        self.data = open(self.config['data_file'], 'w')
        # Create the BPF instance
        self.bpf = BPF(src_file=self.config['program_file'])


# A global instance of the context class since the BPF event callback needs to access it
BPF_CTX = BpfContext(sys.argv[1])

_BPF_SLEEP = 1
_BPF_POLL_SLEEP = 500


def ebpf_runner():
    """ Attaches the probes to the given program locations (functions, usdt, cache events, ...)
    and runs the profiled command to gather the performance data.
    """
    # Attach the probes
    _attach_functions(BPF_CTX.bpf, BPF_CTX.config['func'], BPF_CTX.config['binary'])
    # TODO: the USDT and cache locations are not working properly as of now
    # _attach_usdt(u, conf['usdt'])
    # _attach_counters(bpf, wrapper_pid)

    # Give BPF time to properly attach all the probes
    time.sleep(_BPF_SLEEP)

    # Run the profiled command
    with utils.nonblocking_subprocess(BPF_CTX.config['command'], {}) as profiled:
        with TimeoutThread(BPF_CTX.config['timeout']) as timeout:
            # Get the BPF output buffer and read the performance data
            BPF_CTX.bpf["records"].open_perf_buffer(_print_event, page_cnt=128)
            while profiled.poll() is None and not timeout.reached():
                try:
                    BPF_CTX.bpf.perf_buffer_poll(_BPF_POLL_SLEEP)
                except KeyboardInterrupt:
                    profiled.terminate()
                    break
    # Wait until all the raw data is written to the data file
    time.sleep(_BPF_SLEEP)
    BPF_CTX.data.close()


def _print_event(_, data, __):
    """ A callback function used when a new performance data is received through the buffer

    :param data: the data part of the performance event
    """
    # Obtain the raw performance record produced by the eBPF process
    duration = BPF_CTX.bpf['records'].event(data)
    # Write the raw data to the output file
    BPF_CTX.data.write(
        '{} {} {} {}\n'.format(duration.pid, duration.id, duration.entry_ns,
                               duration.exit_ns - duration.entry_ns)
    )


def _load_config(config_file):
    """ Load the runtime configuration from the given file.

    :param str config_file: a full path to the runtime configuration file

    :return dict: the configuration dictionary parsed from the JSON file
    """
    with open(config_file, 'r') as json_handle:
        return json.load(json_handle)


def _attach_functions(bpf, function_probes, binary):
    """ Attach all of the function probes to the profiled process

    :param BPF bpf: the BPF object
    :param dict function_probes: the function probes specification
    :param str binary: name of the binary file to attach to
    """
    for func in function_probes.values():
        # Attach the entry function probe
        bpf.attach_uprobe(
            name=binary, sym=func['name'], fn_name='entry_{}'.format(func['name'])
        )
        # Attach the exit function probe
        bpf.attach_uretprobe(
            name=binary, sym=func['name'], fn_name='exit_{}'.format(func['name'])
        )


def _attach_usdt(usdt_context, usdt_probes):
    """ Attach all of the USDT probes to the supplied USDT context object

    :param USDT usdt_context: the USDT context object
    :param dict usdt_probes: the USDT probes specification
    """
    for usdt in usdt_probes.values():
        # If the USDT probe has no pair, attach a single probe
        if usdt['pair'] == usdt['name']:
            usdt_context.enable_probe(probe=usdt['name'], fn_name='usdt_{}'.format(usdt['name']))
        else:
            usdt_context.enable_probe(probe=usdt['name'], fn_name='entry_{}'.format(usdt['name']))
            usdt_context.enable_probe(probe=usdt['name'], fn_name='exit_{}'.format(usdt['name']))


def _attach_cache_counters(bpf, pid):
    """ Attach HW cache counters.

    :param BPF bpf: the BPF object
    :param int pid: the pid of the target process
    """
    # Attach cache miss counter probe
    bpf.attach_perf_event(
        ev_type=PerfType.HARDWARE, ev_config=PerfHWConfig.CACHE_MISSES,
        fn_name="on_cache_miss", sample_period=1, pid=pid)
    # Attach cache access counter probe
    bpf.attach_perf_event(
        ev_type=PerfType.HARDWARE, ev_config=PerfHWConfig.CACHE_REFERENCES,
        fn_name="on_cache_ref", sample_period=1, pid=pid)


if __name__ == '__main__':
    ebpf_runner()
