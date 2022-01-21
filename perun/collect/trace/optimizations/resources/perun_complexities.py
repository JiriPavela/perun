import perun.logic.runner as runner
import perun.utils.log as log
from perun.logic import stats, temp
from perun.utils import get_module
from perun.collect.trace.optimizations.structs import Complexity
from perun.utils.exceptions import StatsFileNotFoundException
from perun.utils.helpers import SuppressedExceptions


def extract(stats_name, make_command, cache, **_):
    """ Run the Perun bounds collector to gather information about inferred bounds and complexity.

    :return dict: a dictionary containing the parsed results of bounds collector
    """
    complexities = {}
    if cache:
        # Try to find and load the stats file if it already exists
        with SuppressedExceptions(StatsFileNotFoundException):
            complexities = stats.get_stats_of(stats_name).get('complexity', {})
            print("Found complexities!")
            for func, complexity in complexities.items():
                complexities[func] = Complexity.from_poly(complexity)
    # Simulate the runner context by manually configured parameters and run the bounds collector
    if not complexities:
        print("Computing complexities!")
        collection_report, prof = runner.run_all_phases_for(
            get_module('perun.collect.inferbounds.run'), 'collector', {'make_command': make_command}
        )
        if not collection_report.is_ok():
            log.error(
                "static bounds analysis failed: {}".format(collection_report.message),
                recoverable=True
            )
            return {}
        # Parse the collector output and store the local and total bounds
        for resource in prof['global']['resources']:
            complexities.setdefault(resource['uid']['function'], []).append(Complexity.from_poly(resource['class']))
        for func, func_bounds in complexities.items():
            complexities[func] = Complexity.max(func_bounds)

    return complexities


def store(stats_name, bounds_map, cache, **_):
    """ Store the internal bounds map structure into the 'stats' directory

    :param str stats_name: name of the stats file
    :param Dict bounds_map: the internal call graph format
    :param bool cache: sets the cache on / off configuration
    """
    if cache:
        # Do not save the file again if it already exists
        with SuppressedExceptions(StatsFileNotFoundException):
            stats.get_stats_file_path(stats_name, check_existence=True)
            return

    serialized = {func: complexity.name for func, complexity in bounds_map.items()}

    stats.add_stats(stats_name, ['complexity'], [serialized])
    temp.store_temp('optimization/{}.json'.format(stats_name), serialized, json_format=True)