"""TODO: Write short docstring of the new collector

TODO: Write long docstring of the new collector
"""

import click
import json
import os
import time as systime

from subprocess import SubprocessError

import perun.logic.runner as runner
import perun.utils.log as log
import perun.utils as utils
from perun.utils.structs import CollectStatus

_INFER_CMD = 'infer'
_INFER_PARAMS= ['--cost-only', '--keep-going']


def collect(make_command, **kwargs):
    """Runs the infer with the following command

        $ infer --cost-only --keep-going -- <make_command>

    """
    log.info("Running infer using make command '{}'". format(
        make_command
    ))

    before_analysis = systime.time()
    try:
        utils.run_safely_external_command("make clean", check_results=True)
        cmd = _INFER_CMD + " " + " ".join(_INFER_PARAMS) + f" -- {make_command}"
        out, _ = utils.run_safely_external_command(cmd, check_results=True)
        out = out.decode('utf-8')
    except SubprocessError as sub_err:
        log.failed()
        return CollectStatus.ERROR, str(sub_err), dict(kwargs)
    overall_time = systime.time() - before_analysis

    # Parse resources
    target_resource_file = os.path.join('infer-out', 'costs-report.json' ) 
    with open(target_resource_file, 'r') as target_handle:
        data = json.load(target_handle)
    resources = []
    for resource in data:
        cost = resource['exec_cost']['hum']
        resources.append({
            'uid': {
                'function': resource['procedure_name'],
                'line': resource['loc']['lnum'],
                'column': resource['loc']['cnum'],
                'source': resource['loc']['file'] 
            },
            'bound': cost['hum_polynomial'],
            'class': 'O(∞)' if cost['big_o'] == 'Top' else \
            ('O(1)' if cost['hum_degree'] == "0" else "O(n^{})".format(cost['hum_degree'])),
            'type': 'total bound'
        })

    log.done()
    return CollectStatus.OK, "status message", {'profile': {
        'global': {
            'timestamp': overall_time,
            'resources': resources
        }
    }}


@click.command()
@click.pass_context
@click.option('--make-command', '-m', metavar='<make>',
              help='Command, that compiles the sources for the infer')
def inferbounds(ctx, **kwargs):
    """TODO: Write documentation of the CLI"""
    runner.run_collector_from_cli_context(ctx, 'inferbounds', kwargs)
