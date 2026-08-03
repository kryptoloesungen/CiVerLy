r"""Benchmark CiVerLy."""

from civerly.solvers import SOLVING_STATUS
from civerly.util import suppress_output
from civerly.model_options import OPTIMIZATION
from civerly.model_options import InvalidModelOptionException


def benchmark(CM):
    r"""
    Generate benchmarks for the given ciphers and models.

    INPUT:

        - ``CM`` -- list; list of tuples ``(ciphers, model_options)`` where
          ``ciphers`` is a list of ciphers.

    OUTPUT:

        - a list of tables. each table corresponds to one ``(ciphers, model_options)``
          tuple. Within a table, for MILP, each row corresponds to one cipher.
          For SAT, there are also the timings for the individual models.

    EXAMPLES:

        We benchmark two models, one for the AES and one for CRAFT::

            sage: # optional - scip espresso cryptominisat
            sage: from civerly.benchmark import benchmark
            sage: from civerly.cipher_implementations.aes import AES_CVL
            sage: from civerly.cipher_implementations.craft import CRAFT_CVL
            sage: from civerly.model_options import *
            sage: from pathlib import Path
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
            sage: for row in T[0]: print(row)
            ['Name', '\\#Variables', '\\#Constraints', '$t_{M}$', '$t_{S}$', 'w']
            ['1r-AES', 320, 305, ..., ..., 1]
            ['2r-AES', 644, 653, ..., ..., 5]
            ['3r-AES', 968, 1001, ..., ..., 9]
            ['4r-AES', 1292, 1349, ..., ..., 25]
            sage: for row in T[1]: print(row)
            ['Name', 'Weight Bound', '\\#Variables', '\\#Clauses', '$t_{M}$', '$t_{S}$', 'Result']
            ['1r-CRAFT', '', 2736, 6161, ..., ..., 2]
            ['', 50, 6736, 14090, ..., ..., 'SAT']
            ['', 25, 4736, 10165, ..., ..., 'SAT']
            ['', 12, 3696, 8124, ..., ..., 'SAT']
            ['', 6, 3216, 7182, ..., ..., 'SAT']
            ['', 3, 2976, 6711, ..., ..., 'SAT']
            ['', 1, 2816, 6397, ..., ..., 'UNSAT']
            ['', 2, 2896, 6554, ..., ..., 'SAT']
            ['2r-CRAFT', '', 5088, 11681, ..., ..., 4]
            ['', 50, 13088, 27690, ..., ..., 'SAT']
            ['', 25, 9088, 19765, ..., ..., 'SAT']
            ['', 12, 7008, 15644, ..., ..., 'SAT']
            ['', 6, 6048, 13742, ..., ..., 'SAT']
            ['', 3, 5568, 12791, ..., ..., 'UNSAT']
            ['', 5, 5888, 13425, ..., ..., 'SAT']
            ['', 4, 5728, 13108, ..., ..., 'SAT']

        For a pretty printing, you may use ``tabulate``::

            sage: # optional - scip espresso cryptominisat
            sage: from tabulate import tabulate
            sage: print(tabulate(T[0], headers="firstrow")) # random
            Name      \#Variables    \#Constraints    $t_{M}$    $t_{S}$    w
            ------  -------------  ---------------  ---------  ---------  ---
            1r-AES            320              305  0.0231313  0.0256079    1
            2r-AES            644              653  0.0969026  0.0258068    5
            3r-AES            968             1001  0.291588   0.0682419    9
            4r-AES           1292             1349  0.30492    0.18162     25
            sage: print(tabulate(T[1], headers="firstrow")) # random
            Name      Weight Bound      \#Variables    \#Clauses     $t_{M}$    $t_{S}$  Result
            --------  --------------  -------------  -----------  ----------  ---------  --------
            1r-CRAFT                           2736         6161  0.199667    0.404689   2
                      50                       6736        14090  0.0122832   0.0409576  SAT
                      25                       4736        10165  0.0096292   0.0716709  SAT
                      12                       3696         8124  0.00785537  0.0542998  SAT
                      6                        3216         7182  0.00768648  0.0429798  SAT
                      3                        2976         6711  0.00691862  0.0307788  SAT
                      1                        2816         6397  0.00676898  0.0202453  UNSAT
                      2                        2896         6554  0.00675746  0.0251838  SAT
            2r-CRAFT                           5088        11681  0.439158    1.04131    4
                      50                      13088        27690  0.0241171   0.187774   SAT
                      25                       9088        19765  0.01925     0.191002   SAT
                      12                       7008        15644  0.0165875   0.137465   SAT
                      6                        6048        13742  0.0150202   0.0875038  SAT
                      3                        5568        12791  0.0141926   0.0591163  UNSAT
                      5                        5888        13425  0.0147129   0.0795579  SAT
                      4                        5728        13108  0.0144167   0.0681787  SAT
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
                v = cipher._model.number_of_variables()
                c = cipher._model.number_of_constraints()
            elif model_options.optimization == OPTIMIZATION.SAT:
                v = cipher._model.nvars()
                c = len(cipher._model.clauses())
                row.append("") # empty weight bound
            else:
                raise InvalidModelOptionException(model_options.optimization, OPTIMIZATION)

            row.append(v)
            row.append(c)
            row.append(cipher.model_time)
            row.append(cipher.solve_time)
            if cipher.results[-1]["status"] == SOLVING_STATUS.SUCCESS:
                row.append(cipher.results[-1]["objective_value"])
            elif cipher.results[-1]["status"] == SOLVING_STATUS.TIMEOUT:
                lower = cipher.results[-1]["objective_bounds"][0]
                upper = cipher.results[-1]["objective_bounds"][1]
                row.append(f"[{lower}, {upper}]")
            table.append(row)

            if model_options.optimization == OPTIMIZATION.SAT:
                for weight, result in cipher.results[-1]["trace"].items():
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

