""" Specification of the new call graph representation.

1. Use networkx DiGraph.
    A. Nodes: function name.
    B. Node attributes: dict of custom objects {'base', 'level', 'cfg', ?}
    C. No separate CFG to save space, instead, CFG is an attribute of the CG node.
2. The call graph class should also contain some identification of the extraction source
   and additional context information:
    1. Networkx graph.
    2. Graph flavours.
    3. Binary and/or source files used for the extraction (substitute with Project when the Tracer
       refactoring is done).
    4. VCS-specific version identification:
        - When the repository contains no local uncommitted changes, use the VCS hash.
        - Otherwise, use the ID of the current dirty version (should be supplied by Perun). The ID
          will possibly contain hash, timestamp and dirty/clean flag. This ID will be used to match
          the CG to the actual dirty sub-version.
    5. Call graph version VCS-hash (identifies the extraction source, i.e., files from #2.3):
        - Can be used to check if we already have a matching call graph stored in the file system.
            - However, allow to force re-extract a call graph (e.g., in case something changed, such
              as extraction module / library version, but it is not affecting the hash).
        - We can't use the VCS version hash here, since it may contain changes to files irrelevant
          from the CG extraction point of view (e.g., change to a README won't affect the CG).
        - Use VCS-specific hashing algorithm (e.g., git hash-object).
        - The collection of files must be sorted!
    6. Profiling configuration ID.
        - The optimization settings is irrelevant for a raw and static CG flavours.
    7. Optimization configuration ID.
    8. Dirty flag, representing whether the call graph was extracted while at least one file from
       #2.3 is modified (in any way, including renames) according to the VCS.
    9. The status (output from the VCS status and from os stat) + hashes of the changed, untracked
       and not-in-vcs files from #2.3. Store it as an accompanying file to the call graph file,
       preferably in a compressed format.
3. We must support multiple flavours of a CG:
    1. Raw; extracted by <tool>. Not all stored nodes need to be reachable from main.
        - There can be multiple raw instances, one for each extraction tool.
    2. Static; built from raw, remove all unreachable edges and nodes.
    3. Dynamic; built from the current run call graph. CFG must be obtained from the raw CG.
        - There can be additional dynamic instances for different profiling IDs.
    4. Mixed; combination of Static and Dynamic CGs to obtain a more general CG.
    5. Generic (abstract); a special flavour that represents a subsets of other flavours.
    A. In general, all of the CG flavours must be obtainable in a single Tracer run.
    B. However, it is not required. Only certain flavours may be extracted if requested by the user
       or decided by, e.g., the optimization engine.
    C. The edges and nodes will contain an attribute 'type' with information about the membership
       of the element into a subset of the flavours. During the extraction or loading, the
       requested flavour will be obtained as a subgraph.
    D. Some other node or edge attributes (e.g., level) may be specific to a certain flavour.
    E. Dynamic and Mixed flavours will be approximations if the run was optimized.
        - Use the same dynamic CG as in the previous version but remove:
            a. nodes that refer to deleted functions,
            b. edges that were removed in the Static CG.
4. Each CG should have entry points specified. The entry points are used, e.g., in level estimation.
    A. Executable binaries (optionally with libraries): we can assume that entry point is 'main'.
    B. Standalone libraries: we must somehow reconstruct the entry points.
        - Scout the extraction tools.
5. The call graph must be serializable, ideally compressed json.
    - Pickle would be the best, but unstable w.r.t. API changes etc.
    A. It must be possible to combine multiple flavour CG files with compatible configuration into
       a single file for storage optimization.
    B. Moreover, the Dynamic and Mixed flavours may be updated with subsequent runs (even with
       different workload / arguments). The only relevant differentiator is the VCS hash.
6. The CG file (A) and version status (B) name formats:
    A. sub_<cg-version-hash>_<c|d>/<profiling-ID>_<r+s+d+m>_<o|f>_<a+...>.cg.bz2
        - <r+s+d+m> specifies the flavours of the stored call graph.
            - E.g., 'rd' identifies a generic call graph, containing both raw and dynamic flavours.
        - <c|d> specifies flags: (clean | dirty)
        - <o|f> specifies flags: (optimized | full)
        - <a+...> specifies static CG extraction tools (angr, ...)
    - example: sub_c9b8cdc7_c/nightly_rd_f_a.cg.bz2
    B. sub_<cg-version-hash>_<c|d>/<profiling-ID>_<timestamp>.vinfo.bz2
    - example: sub_c9b8cdc7_c/nightly_2022-04-30-21-22-15.vinfo.bz2
"""


class CallGraph:
    pass
