r"""Benchmark CiVerLy."""

from civerly.solvers import solve
from civerly.solvers import SOLVING_STATUS
from civerly.util import suppress_output
from civerly.model_options import GRANULARITY
from civerly.model_options import OPTIMIZATION

import shutil
import time

from civerly.solvers import get_objective_value
from civerly.solvers import get_objective_bounds
from civerly.solvers import optimize_sat


def benchmark(CM=None, remove_files=False, only_models=False,
              solving_time_limit=None):
    """
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
        ....:   solver=SOLVER.SCIP,
        ....:   path=path)
        sage: aes = [AES_CVL(R=r, name=f"{r}r-AES") for r in range(1, 10)]
        sage: CM = [(aes, model_options)]
        sage: benchmark(CM) # optional - scip
        ...
        sage: import shutil
        sage: shutil.rmtree("DOCTEST-Benchmark-AES-Models", ignore_errors=True)
    """
    for ciphers, model_options in CM:
        optimization = model_options.optimization.name
        mode = model_options.cryptanalysis.name
        granularity = model_options.granularity.name
        solver = model_options.solver.name
        if model_options.linear_layer_modeling:
            ll = model_options.linear_layer_modeling.name
        else:
            ll = None
        if model_options.sbox_modeling:
            sbox = model_options.sbox_modeling.name
        else:
            sbox = None
        mo = f"{optimization}-{mode}-{granularity}-{ll}-{sbox}-{solver}"
        caption = f"\\texttt{{\scriptsize {mo}}}."  # noqa: W605
        caption = caption.replace("_", "\_")  # noqa: W605

        if model_options.optimization == OPTIMIZATION.MILP:
            print("\\begin{longtable}{c | c c | c | c c c}")
        elif model_options.optimization == OPTIMIZATION.SAT:
            print("\\begin{longtable}{l r | r r | r | r l c}")
        print(f"\\caption{{{caption}}}\\\\")
        s = "Name & "
        if model_options.optimization == OPTIMIZATION.SAT:
            s += "Weight Bound & "
        s += "\\#Variables & "
        if model_options.optimization == OPTIMIZATION.MILP:
            s += "\\#Constraints & "
        elif model_options.optimization == OPTIMIZATION.SAT:
            s += "\\#Clauses & "
        s += "$t_{M}$ & $t_{S}$ & "
        if model_options.optimization == OPTIMIZATION.MILP:
            if model_options.granularity == GRANULARITY.WORDWISE:
                s += "\\# act. S. & "
            else:
                s += "\\# -\\log\_2(p)  & "  # noqa: W605
        elif model_options.optimization == OPTIMIZATION.SAT:
            s += "Result & "
        s += "Optimal\\\\"
        print(s)
        print("\\hline\\endhead")

        for cipher in ciphers:
            table = []
            with suppress_output():

                model_start = time.time()
                model = cipher.model(model_options)
                model_stop = time.time()
                model_time = round(model_stop - model_start, 2)

                obj = ""
                solve_time = ""
                if not only_models:
                    solve_start = time.time()

                    if model_options.optimization == OPTIMIZATION.MILP:
                        name = f"{cipher.name}_{model_options.solver.name}"
                        log_file_name = model_options.path / f"{name}.log"
                        sol_file_name = model_options.path / (cipher.name + ".sol")
                        status = solve(model_options.path / (cipher.name + ".mps"),
                                       sol_file_name,
                                       solver=model_options.solver,
                                       time_limit=solving_time_limit,
                                       log_file_name=log_file_name)
                        solve_stop = time.time()
                        solve_time = round(solve_stop - solve_start, 2)
                        if status is None:
                            obj = get_objective_value(sol_file_name,
                                                      model_options.solver)
                            solve_time = f"{solve_time}s"
                        elif status == SOLVING_STATUS.TIMEOUT:
                            solve_time = f"{solving_time_limit}s$^{{\\dagger}}$"
                            bounds = get_objective_bounds(log_file_name,
                                                          model_options.solver)
                            if bounds == [None, None]:
                                obj = "-"
                            else:
                                obj = f"[{bounds[0]}, {bounds[1]}]"
                        else:
                            pass

                    elif model_options.optimization == OPTIMIZATION.SAT:
                        benchmarks = optimize_sat(
                            model_options.path / (cipher.name + ".cnf"),
                            model_options.path / (cipher.name + ".sat"),
                            model_options=model_options,
                            time_limit=solving_time_limit,
                            benchmark=True
                        )
                        solve_stop = time.time()
                        solve_time = round(solve_stop - solve_start, 2)
                        # first row
                        s = f"{cipher.name} & - & {model.nvars()} & "
                        nclauses = len(model.clauses())
                        s += f"{nclauses} & {round(model_time, 2)}s & - & & \\\\*"
                        table.append(s)
                        model_time_total = model_time
                        solve_time_total = 0
                        time_out = False
                        for row in benchmarks:
                            s = f" & {row["bound"]} & {row["nvars"]} & "
                            s += f"{row["nclauses"]} & {round(row["t_model"], 2)}s & "
                            s += f"{round(row["t_solve"], 2)}s"
                            if row["result"] == SOLVING_STATUS.TIMEOUT:
                                s += "$^{\\dagger}$ & - & \\\\*"
                                time_out = True
                            else:
                                s += f" & {row["result"]} & \\\\*"
                            table.append(s)
                            model_time_total += row["t_model"]
                            solve_time_total += row["t_solve"]
                        # last row
                        s = f" & & & & {round(model_time_total, 2)}s & "
                        s += f"{round(solve_time_total, 2)}s"
                        if time_out:
                            row = benchmarks[-1]
                            s += "$^{\\dagger}$ & "
                            s += f"[{row["W_MIN"]}, {row["W_MAX"]}]"
                            s += " & \\\\*"
                        else:
                            bound = get_objective_value(
                                model_options.path / (cipher.name + ".sat"),
                                model_options.solver)
                            s += " & "
                            s += f"{bound} & \\cmark \\\\*"
                        table.append(s)
                        table.append("\\hline")

            if model_options.optimization == OPTIMIZATION.MILP:
                s = f"{cipher.name} & {model.number_of_variables()} & "
                s += f"{model.number_of_constraints()} & {model_time}s & "
                s += f"{solve_time} & {obj} &  \\\\"
                print(s)

            if model_options.optimization == OPTIMIZATION.SAT:
                for row in table:
                    print(row)

        if remove_files:
            shutil.rmtree(model_options.path)

        print("\\end{longtable}")
        print()
