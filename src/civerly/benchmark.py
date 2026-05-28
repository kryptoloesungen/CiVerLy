r"""Benchmark CiVerLy."""

from civerly.solvers import SOLVING_STATUS
from civerly.util import suppress_output
from civerly.model_options import GRANULARITY
from civerly.model_options import OPTIMIZATION
from civerly.model_options import InvalidModelOptionException

import shutil
import time


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

        sage: from civerly.benchmark import benchmark
        sage: from civerly.cipher_implementations.aes import AES_CVL
        sage: from civerly.model_options import *
        sage: from pathlib import Path
        sage: path = Path("./DOCTEST-Benchmark-AES-Models/")
        sage: model_options = MODEL_OPTIONS(
        ....:   cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
        ....:   optimization=OPTIMIZATION.MILP,
        ....:   granularity=GRANULARITY.WORDWISE,
        ....:   linear_layer_modeling=LINEAR_LAYER_MODELING.BRANCH_NUMBER,
        ....:   milp_solver=SOLVER.SCIP,
        ....:   path=path)
        sage: aes = [AES_CVL(R=r, name=f"{r}r-AES") for r in range(1, 10)]
        sage: CM = [(aes, model_options)]
        sage: # benchmark(CM) # optional - scip
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

