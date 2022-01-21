"""
Static Baseline optimization is based on the formal static analysis of the project sourcecode.
Specifically, we leverage the resource bounds analysis(with the focus on amortized complexity
analysis), which is implemented in the Perun Bounds collector: a wrapper over the
well-established Loopus tool

"""

from perun.collect.trace.optimizations.structs import Complexity


def complexity_filter(call_graph, bounds_map, complexity, keep_top):
    """ The Static Baseline method.

    :param CallGraphResource call_graph: the CGR optimization resource
    :param Complexity complexity: complexity threshold for functions to be excluded from profiling
    :param int keep_top: protected top CG levels

    :return set: a set of functions that are removed by the method
    """
    if bounds_map:
        return _call_graph_filter(call_graph, bounds_map, complexity, keep_top)


def _call_graph_filter(call_graph, bounds_map, complexity, keep_top):
    """ Compare the inferred complexities with the threshold and remove functions that match the
    specified complexity degree.

    :param CallGraphResource call_graph: the CGR optimization resource
    :param dict bounds_map: a dictionary containing the parsed results of bounds collector
    :param Complexity complexity: complexity threshold for functions to be excluded from profiling
    :param int keep_top: protected top CG levels

    :return set: a set of functions that are removed by the method
    """
    filter_list = []
    # Assign complexity to all CG functions, if we failed to infer one, use the default
    for level in reversed(call_graph.levels[keep_top:]):
        for func in level:
            func_complexity = bounds_map.get(func, Complexity.GENERIC)
            call_graph[func]['complexity'] = Complexity(func_complexity)
            # Filter functions that are below the threshold
            if func_complexity <= complexity:
                filter_list.append(func)
    return set(filter_list)
