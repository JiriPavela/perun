""" Assembles the eBPF collection program according to the supplied probe specification.
Inspired by:
 - https://github.com/iovisor/bcc/blob/master/tools/funcslower.py
 - https://github.com/iovisor/bcc/blob/master/tools/funccount.py
"""

from perun.collect.trace.watchdog import WATCH_DOG


def assemble_ebpf_program(src_file, probes, **_):
    """Assembles the eBPF program.

    :param str src_file: path to the program file, that should be generated
    :param Probes probes: the probes object
    """
    WATCH_DOG.info("Attempting to assembly the eBPF program '{}'".format(src_file))

    # Open the eBPF program file
    with open(src_file, 'w') as prog_handle:
        # Initialize the program
        sampled_count = len(probes.sampled_func) + len(probes.sampled_usdt)
        _add_structs_and_init(prog_handle, len(probes.func) + len(probes.usdt), sampled_count)

        # Add entry and exit probe handlers for every traced function
        for func_probe in sorted(probes.func.values(), key=lambda value: value['name']):
            _add_entry_probe(prog_handle, func_probe)
            _add_exit_probe(prog_handle, func_probe)
        # TODO: add USDT and cache tracing after BPF properly supports it

    WATCH_DOG.info("eBPF program successfully assembled")
    WATCH_DOG.log_probes(len(probes.func), len(probes.usdt), src_file)


def _add_structs_and_init(handle, probe_count, sampled_count):
    """ Add include statements, perf_event struct and the required BPF data structures.

    :param TextIO handle: the program file handle
    :param int probe_count: the number of traced function and USDT locations
    :param int sampled_count: the number of sampled probes
    """
    # Create the sampling BPF array if there are any sampled probes
    if sampled_count > 0:
        sampling_array = 'BPF_ARRAY(sampling, u32, {sampled});'.format(sampled=sampled_count)
    else:
        sampling_array = '// sampling array omitted'
    # The initial program code
    prog_init = """
#include <linux/sched.h>     // for TASK_COMM_LEN
#include <uapi/linux/bpf_perf_event.h>

struct duration_data {{
    u32 id;
    u32 pid;
    u64 entry_ns;
    u64 exit_ns;
    char comm[TASK_COMM_LEN];
}};

// BPF_ARRAY(cache, u64, 2);
BPF_ARRAY(timestamps, u64, {probes});
{sampling_array}
BPF_PERF_OUTPUT(records);
""".format(probes=probe_count, sampling_array=sampling_array)
    handle.write(prog_init)


def _add_entry_probe(handle, probe):
    """ Add entry code for the given probe.

    :param TextIO handle: the program file handle
    :param dict probe: the traced probe
    """
    probe_template = """
int entry_{name}(struct pt_regs *ctx)
{{
    u32 id = {probe_id}; 
{sampling_before}
{entry_body}
{sampling_after}
    
    return 0;
}}
""".format(name=probe['name'], probe_id=probe['id'],
           sampling_before=_create_sampling_before(probe['sample']),
           entry_body=_create_entry_body(),
           sampling_after=_create_sampling_after(probe['sample'])
           )
    handle.write(probe_template)


def _add_exit_probe(handle, probe):
    """ Add exit code for the given probe.

    :param TextIO handle: the program file handle
    :param dict probe: the traced probe
    """
    probe_template = """
int exit_{name}(struct pt_regs *ctx)
{{
    u64 exit_timestamp = bpf_ktime_get_ns();
    u32 id = {probe_id};
    
    u64 *entry_timestamp = timestamps.lookup(&id);
    if (entry_timestamp == NULL || *entry_timestamp == 0) {{
        return 0;
    }}
    
    struct duration_data data = {{}};
    data.id = id;
    data.pid = bpf_get_current_pid_tgid();
    data.entry_ns = *entry_timestamp;
    data.exit_ns = exit_timestamp;
    
    (*entry_timestamp) = 0;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    records.perf_submit(ctx, &data, sizeof(data));
    
    return 0;
}}
""".format(name=probe['name'], probe_id=probe['id'])
    handle.write(probe_template)


def _add_single_probe(handle, probe):
    """ Add code for probe that has no paired probe, e.g. single USDT locations with no pairing.

    :param TextIO handle: the program file handle
    :param dict probe: the traced probe
    """
    probe_template = """
    int usdt_{name}(struct pt_regs *ctx)
    {{
        u64 usdt_timestamp = bpf_ktime_get_ns();

        struct duration_data data = {{}};
        data.id = {probe_id};
        data.pid = bpf_get_current_pid_tgid();
        data.entry_ns = usdt_timestamp;
        data.exit_ns = usdt_timestamp;

        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        records.perf_submit(ctx, &data, sizeof(data));

        return 0;
    }}
""".format(name=probe['name'], probe_id=probe['id'])
    handle.write(probe_template)


def _add_cache_probes(handle):
    """ Add code for cache probes that simply counts the HW cache events.
    Inspired by: https://github.com/iovisor/bcc/blob/master/tools/llcstat.py

    :param TextIO handle: the program file handle
    """

    template = """
int on_cache_ref(struct bpf_perf_event_data *ctx) {
    cache.increment(0, ctx->sample_period);
    return 0;
}

int on_cache_miss(struct bpf_perf_event_data *ctx) {
    cache.increment(1, ctx->sample_period);
    return 0;
}
"""
    handle.write(template)


def _create_sampling_before(sample_value):
    """ Generate code that goes before the body for sampled probes.

    :param int sample_value: the sample value of the probe
    :return str: the generated code chunk
    """
    if sample_value == 1:
        return "   // sampling code omitted"
    return """
    u32 *sample = sampling.lookup(&id);
    if (sample == NULL) {
        return 0;
    }
    
    if (*sample == 0) {"""


def _create_sampling_after(sample_value):
    """ Generate code that goes after the body for sampled probes.

    :param int sample_value: the sample value of the probe
    :return str: the generated code chunk
    """
    if sample_value == 1:
        return "   // sampling code omitted"
    return """
    }}
        
    (*sample)++;
    if (*sample == {sample_value}) {{
        (*sample) = 0;
    }}""".format(sample_value=sample_value)


def _create_entry_body():
    """ Generate the generic body for all entry probes.

    :return str: the generated code chunk
    """
    return """
    u64 entry_timestamp = bpf_ktime_get_ns();        
    timestamps.update(&id, &entry_timestamp);"""
