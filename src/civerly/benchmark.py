r"""Benchmark CiVerLy."""

from civerly.solvers import SOLVING_STATUS
from civerly.util import suppress_output
from civerly.model_options import OPTIMIZATION
from civerly.model_options import InvalidModelOptionException


def benchmark(CM):
    Generate benchmarks for the given ciphers and models.

    The results are printed as latex code.

    INPUT:

        - ``CM`` -- list; list of tuples ``(ciphers, model_options)`` where
          ``ciphers`` is a list of ciphers.
        - ``solving_time_limit``  -- integer (default ``None``); time limit (in
          seconds) for solving an individual model

    .. WARNING:

        This requires the used solvers (by default all three) to be installed.

    EXAMPLES::

        sage: # optional - scip, espresso, cryptominisat
        sage: from civerly.benchmark import benchmark
        sage: from civerly.cipher_implementations.aes import AES_CVL
        sage: from civerly.cipher_implementations.craft import CRAFT_CVL
        sage: from civerly.model_options import *
        sage: from pathlib import Path
        sage: from tabulate import tabulate
        sage: import tempfile
        sage: with tempfile.TemporaryDirectory(delete=False) as tmpdir:
        ....:   model_options_aes = MODEL_OPTIONS(
        ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
        ....:     optimization=OPTIMIZATION.MILP,
        ....:     granularity=GRANULARITY.WORDWISE,
        ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.BRANCH_NUMBER,
        ....:     milp_solver=SOLVER.SCIP,
        ....:     path=Path(tmpdir))
        sage: with tempfile.TemporaryDirectory(delete=False) as tmpdir:
        ....:   model_options_craft = MODEL_OPTIONS(
        ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
        ....:     optimization=OPTIMIZATION.SAT,
        ....:     granularity=GRANULARITY.BITWISE,
        ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.EXCLUDE_ODD,
        ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
        ....:     sat_solver=SOLVER.CRYPTOMINISAT,
        ....:     logic_minimizer=SOLVER.ESPRESSO,
        ....:     path=Path(tmpdir))
        sage: aes = [AES_CVL(R=r, name=f"{r}r-AES") for r in range(1, 5)]
        sage: craft = [CRAFT_CVL(R=r, name=f"{r}r-CRAFT") for r in range(1, 3)]
        sage: CM = [(aes, model_options_aes), (craft, model_options_craft)]
        sage: T = benchmark(CM)
        sage: print(tabulate(T[0], headers="firstrow"))
        Name       \#Variables    \#Constraints    $t_{M}$    $t_{S}$    w
        -------  -------------  ---------------  ---------  ---------  ---
        1r-AES             256              241  ...        ...          1
        2r-AES             548              557  ...        ...          5
        3r-AES             840              873  ...        ...          9
        4r-AES            1132             1189  ...        ...         25
        sage: print(tabulate(T[1], headers="firstrow"))
        Name      Weight Bound      \#Variables    \#Clauses     $t_{M}$    $t_{S}$  Result
        --------  --------------  -------------  -----------  ----------  ---------  --------
        1r-CRAFT                           2736         6161  ...         ...        2
                  50                       6736        14090  ...         ...        SAT
                  25                       4736        10165  ...         ...        SAT
                  12                       3696         8124  ...         ...        SAT
                  6                        3216         7182  ...         ...        SAT
                  3                        2976         6711  ...         ...        SAT
                  1                        2816         6397  ...         ...        UNSAT
                  2                        2896         6554  ...         ...        SAT
        2r-CRAFT                           5088        11681  ...         ...        4
                  50                      13088        27690  ...         ...        SAT
                  25                       9088        19765  ...         ...        SAT
                  12                       7008        15644  ...         ...        SAT
                  6                        6048        13742  ...         ...        SAT
                  3                        5568        12791  ...         ...        UNSAT
                  5                        5888        13425  ...         ...        SAT
                  4                        5728        13108  ...         ...        SAT
    """
    tables = []
    for ciphers, model_options in CM:
        if model_options.optimization == OPTIMIZATION.MILP:
            header = ["Name", r"\#Variables", r"\#Constraints", "$t_{M}$", "$t_{S}$", "w"]
        elif model_options.optimization == OPTIMIZATION.SAT:
            header = ["Name", "Weight Bound", r"\#Variables", r"\#Clauses", "$t_{M}$", "$t_{S}$", "Result"]
        else:
            raise InvalidModelOptionException(model_options.optimization, OPTIMIZATION)
        table = [header]
        for cipher in ciphers:
            with suppress_output():
                cipher.analyse(model_options)

            row = [cipher.name]

            if model_options.optimization == OPTIMIZATION.MILP:
                v = cipher.model.number_of_variables()
                c = cipher.model.number_of_constraints()
            elif model_options.optimization == OPTIMIZATION.SAT:
                v = cipher.model.nvars()
                c = len(cipher.model.clauses())
                row.append("") # empty weight bound
            else:
                raise InvalidModelOptionException(model_options.optimization, OPTIMIZATION)

            row.append(v)
            row.append(c)
            row.append(cipher.model_time)
            row.append(cipher.solve_time)
            if cipher.result["status"] == SOLVING_STATUS.SUCCESS:
                row.append(cipher.result["objective_value"])
            elif cipher.result["status"] == SOLVING_STATUS.TIMEOUT:
                lower = cipher.result["objective_bounds"][0]
                upper = cipher.result["objective_bounds"][1]
                row.append(f"[{lower}, {upper}]")
            table.append(row)

            if model_options.optimization == OPTIMIZATION.SAT:
                for weight, result in cipher.result["trace"].items():
                    row = ["", weight]
                    row.append(result["model"].nvars())
                    row.append(len(result["model"].clauses()))
                    row.append(result["model_time"])
                    row.append(result["solve_time"])
                    if result["status"] == SOLVING_STATUS.SUCCESS:
                        row.append("SAT" if result["satisfiability"] else "UNSAT")
                    elif result["status"] == SOLVING_STATUS.TIMEOUT:
                        row.append("-")
                    table.append(row)

        tables.append(table)
    return tables

