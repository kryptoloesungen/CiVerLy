r"""
Utils for interacting with MILP and SAT solvers.
"""

import re
import json
import subprocess
import os
import warnings
import time
import shutil
from pathlib import Path
from enum import Enum

from sage.sat.solvers.dimacs import DIMACS
from civerly.util import _generate_constraints_sum_leq_int_LS24
from civerly.util import suppress_output, _float_or_int
from civerly.util import _to_dict


class SOLVER_CVL:
    """
    The solver to be (automatically) used by CiVerLy. Of course, CiVerLy does
    not implement any solver but simply calls the corresponding solver.

    Supported MILP solvers:

    - SCIP: Open Source and reasonable performance.
    - GLPK: Open Source but only weak performance.
    - Gurobi: Commercial solver (license needed). Best performance.

    Supported SAT solvers:

    - CryptoMiniSat: Open Source solver.
    - CaDiCal: Open Source solver.

    .. NOTE::

        If you are going to solve all models by yourself (e.g. on a different
        machine), you can set this to ``None``.

    .. WARNING::

        Pick a solver only if it is installed on the same machine you are
        running CiVerLy on.
    """

    def __init__(self):
        self.name = "GenericSolver"
        self.status = SOLVING_STATUS.SUCCESS  # default value

        # overwritten for solvers not supporting log files
        self.redirect_stdout = None

    def solve(self, input_file, solution_file,
              log_file=None, time_limit=None):
        """
        Solve the given optimization problem. For MILP and minimizing, this
        simply calls :meth:`invoke`, while for SAT the binary search method
        (formerly `optimize_sat`) is called.
        """
        return self.invoke(
            input_file, solution_file,
            log_file=log_file, time_limit=time_limit
        )

    def invoke(self, input_file, solution_file,
              log_file=None, time_limit=None):
        """
        Solve the given MILP or SAT instance externally.

        INPUT:

            - ``input_file``-- path to the file containing the MILP or SAT

            - ``solution_file``-- path of the file the solution is written to

            - ``log_file``-- path to the solver's log file. Default based on
            ``solution_file`` and ``solver``.

            - ``time_limit``-- integer (default ``None``); time limit in seconds

        OUTPUT:

            - Status, see :class:`civerly.solvers.SOLVING_STATUS`. Further, upon
            successful execution either a ``.sol`` or a ``.sat`` file is created,
            depending on ``solver``. The file will contain the solution, if one
            is found.

        .. NOTE::

            This method is implemented for convenience in case a solver is
            installed on the same machine as CiVerLy.
        """
        assert isinstance(input_file, Path)
        assert isinstance(solution_file, Path)

        # default log file
        if log_file is None:
            parent_dir = solution_file.parent
            name = f"{solution_file.stem}_{self.name}"
            suffix = ".log"
            log_file = parent_dir / (name + suffix)
        else:
            assert isinstance(log_file, Path)

        # you can disable a solver by setting an environment variable
        # with this we simulate that a solver is not installed albeit it is
        # i.e. this is used for testing only
        ENV_DISABLE_PREFIX = "CIVERLY_DISABLE_"
        if ENV_DISABLE_PREFIX+self.name in os.environ:
            raise ValueError(
                f"{self.name} was disabled by setting environment variable "
                f"{ENV_DISABLE_PREFIX+self.name}"
            )

    def process_solution_file(self, solution_file_name):
        pass


class MILP_SOLVER_CVL(SOLVER_CVL):
    def __init__(self):
        super().__init__()
        
    def solve_multiple(self, model_options, cipher=None, time_limit=None):
        r"""
        Find up to *n* solutions using a by-hand blocking approach.

        After each solve the solution is excluded (via ``cipher.exclude_solution``),
        the MILP model is regenerated (via ``cipher.model``), and the solver is invoked again.

        Returns a list of ``(results_dict, objective_value)`` pairs ordered
        from best to worst objective weight.
        """
        input_file  = model_options.path / (cipher.name + ".mps")
        solution_file = model_options.path / (cipher.name + ".sol")
        assert isinstance(input_file, Path)
        assert isinstance(solution_file, Path)

        n = model_options.number_of_solutions

        all_results = []
        solution_index = 0

        while solution_index < n:
            if solution_index == 0:
                sol_file = solution_file
            else:
                sol_file = (
                    solution_file.parent
                    / f"{solution_file.stem}_{solution_index}{solution_file.suffix}"
                )
            self.invoke(input_file, sol_file, time_limit=time_limit)
            r, w = self.process_solution_file(sol_file)

            all_results.append((r, w))
            solution_index += 1

            if solution_index < n and cipher is not None:
                cipher.exclude_solution(model_options, r)
                cipher._finish_milp(model_options, cipher.milp)

        return all_results


class SAT_SOLVER_CVL(SOLVER_CVL):
    def __init__(self):
        super().__init__()

    def solve(self, input_file, solution_file, model_options=None,
              time_limit=None, benchmark=False):
        """
        Repeatedly solve SAT to determine the lowest possible weight.

        Given a SAT with its corresponding ``sum_arr``, this method applies a
        binary search to determine the lowest weight ``w`` for which this SAT is
        solvable and solves it.

        INPUT:

            - ``input_file``-- path to the file containing the SAT

            - ``solution_file``-- path to the file the solution is written to

            - ``model_options`` -- see
            :class:`civerly.model_options.MODEL_OPTIONS`.
            Used to retrieve the ``solver``, ``solve_range`` and
            ``sat_precision``.

            - ``time_limit``-- integer (default ``None``); time limit in seconds

            - ``benchmark``-- (default ``False``); when set to ``True`` return
            details about internal timing. This is used by
            :meth:`civerly.benchmark.benchmark`.

        OUTPUT:

            - None, but upon successful execution a ``.sol`` file is created,
            containing the solution (if found).

        .. NOTE::

            This method is implemented for convenience in case a solver is
            installed on the same machine as CiVerLy.
        """
        assert isinstance(input_file, Path)
        assert isinstance(solution_file, Path)

        if time_limit is not None:
            end_time = int(time.time()+time_limit)

        # shorten variable name
        if model_options is not None:
            pr = model_options.sat_precision
        else:
            pr = 0

        benchmarks = []

        def __get_sum_arr():
            r"""
            Implicit helper function to read and extract the sum_arr from the
            corresponding json file.
            """
            sum_arr_file = input_file.parent / f"{input_file.stem}sum.json"
            with open(sum_arr_file, 'r') as f:
                file_content = json.load(f)

                # Scale all weights by 10**sat_precision
                # (and normalize again later)
                sum_arr = [
                    (weight, var)
                    for weight, var in file_content
                ]
            return sum_arr

        if model_options is not None:
            # scale W_MIN, W_MAX too
            W_MIN = int(model_options.solve_range[0] * 10**pr)
            W_MAX = int(model_options.solve_range[1] * 10**pr)
        else:
            W_MIN, W_MAX = 0, 100

        ALL_SAT, ALL_UNSAT = True, True
        # ---------------------------------------------------------------
        while W_MAX > W_MIN or ALL_UNSAT or ALL_SAT:
            w = (W_MAX + W_MIN) // 2

            # will be appended to benchmarks
            row = {"bound": w}
            row["W_MIN"] = W_MIN
            row["W_MAX"] = W_MAX

            sat = DIMACS()
            sat.read(str(input_file))

            print(
                f"[{float(W_MIN/10**pr):{3+pr}.{pr}f} ,"
                f"{float(W_MAX/10**pr):{3+pr}.{pr}f}] "
                f"(trying w = {float(w/10**pr):{3+pr}.{pr}f}) :",  # noqa
                end=" ",
                flush=True
            )
            start = time.time()
            sat_constraining_prob = _generate_constraints_sum_leq_int_LS24(
                sat,
                __get_sum_arr(),
                int(w)  # cast to int as it is a float with .0 anyway
            )
            stop = time.time()
            row["nvars"] = sat_constraining_prob.nvars()
            row["nclauses"] = len(sat_constraining_prob.clauses())
            row["t_model"] = stop - start

            # temporary files with encoded weight w
            name = f"{input_file.stem}_obj{w}"
            tmp_cnf_file_name = input_file.parent / f"{name}.cnf"
            tmp_sat_file_name = input_file.parent / f"{name}.sat"
            sat_constraining_prob.write(tmp_cnf_file_name)
            if time_limit is not None:
                tmp_time_limit = end_time - int(time.time())
                if tmp_time_limit < 0:
                    return SOLVING_STATUS.TIMEOUT, (W_MIN/10**pr, W_MAX/10**pr)
            else:
                tmp_time_limit = None

            start = time.time()
            status = self.invoke(
                tmp_cnf_file_name,
                tmp_sat_file_name,
                time_limit=tmp_time_limit
            )
            stop = time.time()
            row["t_solve"] = stop - start

            if status is not None:
                if benchmark:
                    row["result"] = status
                    benchmarks.append(row)
                    return benchmarks
                else:
                    e = f"{tmp_sat_file_name} could not be solved."
                    raise AssertionError(e)

            with open(tmp_sat_file_name, 'r') as f:
                result = f.readlines()[0].strip("\n")

            if result in ["UNSAT", "s UNSATISFIABLE"]:
                row["result"] = "UNSAT"
                benchmarks.append(row)
                ALL_SAT = False
                W_MIN, res = (w + 1), "UNSAT"
                if W_MIN > W_MAX:
                    # happens if all models are UNSAT
                    print(res)
                    W_MIN = W_MAX
                    break
            elif result in ["SAT", "s SATISFIABLE"]:
                row["result"] = "SAT"
                benchmarks.append(row)
                ALL_UNSAT = False
                W_MAX, res = w, "SAT"
                if W_MAX == W_MIN:
                    # happens if all models are SAT
                    print(res)
                    break
            else:
                e = f"{tmp_sat_file_name} does not have the expected format."
                e += f" Expected: SAT/UNSAT, got: {result}."
                raise AssertionError(e)

            print(res)

        # ---------------------------------------------------------------

        # put solution in correct file
        name = f"{input_file.stem}_obj{W_MIN}"
        tmp_cnf_file_name = input_file.parent / f"{name}.cnf"
        tmp_sat_file_name = input_file.parent / f"{name}.sat"
        shutil.copyfile(tmp_cnf_file_name, input_file)
        shutil.copyfile(tmp_sat_file_name, solution_file)

        # write optimization value into the sat file
        with open(solution_file, 'a') as f:
            f.write(str(float(W_MIN/10**pr))+"\n")

        if benchmark:
            return benchmarks

        if pr == 0:
            return int(W_MIN)
        return float(W_MIN/10**pr)

    def solve_multiple(self, model_options, cipher=None, time_limit=None):
        r"""
        Find up to *n* solutions ordered by weight (best first).

        **Strategy (by-hand blocking with weight escalation)**

        1. Call :meth:`solve` to find the minimum weight *W* and the first
           solution (binary search).  Before this call the base CNF is saved;
           after the call *input_file* holds the CNF with the weight
           constraint ``<= W``.

        2. For each subsequent solution:

           a. Build a *blocking clause* from the variables in ``sum_arr`` and
              the ``SAT_IN`` variables (indices ``1 … cipher.input_length``).
              For each variable *v* in this set, the clause literal is
              ``¬v`` if *v* was **1** in the previous solution, or ``v``
              otherwise.  This ensures the next solution must differ in at
              least one of these bits.

           b. Append the clause to *input_file* (accumulating across
              iterations) and invoke the solver.

           c. If the result is UNSAT, all solutions at the current weight are
              exhausted.  The weight bound is incremented by one, the CNF is
              rebuilt from the saved base file with the new ``<= W+1``
              constraint, and solving continues.  This repeats until SAT is
              found or the upper bound (``model_options.solve_range[1]``) is
              reached.

        Returns a list of ``(results_dict, objective_value)`` pairs ordered
        best to worst objective weight.
        """
        input_file  = model_options.path / (cipher.name + ".cnf")
        solution_file = model_options.path / (cipher.name + ".sat")
        assert isinstance(input_file, Path)
        assert isinstance(solution_file, Path)

        n = model_options.number_of_solutions

        pr = model_options.sat_precision if model_options is not None else 0
        W_MAX_INT = (
            int(model_options.solve_range[1] * 10**pr)
            if model_options is not None else 100
        )

        # Save the base CNF before solve() overwrites input_file.
        base_cnf_file = (
            input_file.parent / f"{input_file.stem}_base.cnf"
        )
        shutil.copyfile(input_file, base_cnf_file)

        # --- Step 1: find minimum weight and first solution -----------------
        weight = self.solve(
            input_file, solution_file,
            model_options=model_options, time_limit=time_limit
        )
        current_weight_int = int(round(weight * 10**pr))
        first_result, _ = self.process_solution_file(solution_file)
        all_results = [(first_result, weight)]

        if n <= 1:
            return all_results

        # sum_arr is needed for weight-escalation (rebuilding CNF at a new bound).
        sum_arr_file = (
            input_file.parent / f"{input_file.stem}sum.json"
        )
        with open(sum_arr_file, 'r') as _f:
            sum_arr = json.load(_f)

        # --- Step 2: enumerate additional solutions -------------------------
        solution_index = 1
        while solution_index < n:
            prev_result = all_results[-1][0]

            cipher.exclude_solution(model_options, prev_result)

            tmp_sat_file = (
                input_file.parent
                / f"{input_file.stem}_sol{solution_index}.sat"
            )

            status = self.invoke(input_file, tmp_sat_file,
                                 time_limit=time_limit)
            if status is not None:
                break  # solver error or timeout

            with open(tmp_sat_file, 'r') as _f:
                result_line = _f.readlines()[0].strip()

            if result_line in ("UNSAT", "s UNSATISFIABLE"):
                # All solutions at current_weight_int are exhausted.
                # Rebuild from the base CNF at increasing weights until SAT.
                advanced = False
                while current_weight_int < W_MAX_INT:
                    current_weight_int += 1
                    base_sat = DIMACS()
                    base_sat.read(str(base_cnf_file))
                    new_cnf = _generate_constraints_sum_leq_int_LS24(
                        base_sat, sum_arr, current_weight_int
                    )
                    new_cnf.write(input_file)

                    status = self.invoke(input_file, tmp_sat_file,
                                         time_limit=time_limit)
                    if status is not None:
                        break  # solver error or timeout

                    with open(tmp_sat_file, 'r') as _f:
                        result_line = _f.readlines()[0].strip()

                    if result_line not in ("UNSAT", "s UNSATISFIABLE"):
                        advanced = True
                        break

                if not advanced or status is not None:
                    break  # no more solutions in range

            # Process the SAT result (whether at the original weight or a new one).
            current_weight = (
                current_weight_int if pr == 0
                else float(current_weight_int / 10**pr)
            )
            with open(tmp_sat_file, 'a') as _f:
                _f.write(str(float(current_weight)) + "\n")

            result, w = self.process_solution_file(tmp_sat_file)
            all_results.append((result, w))
            solution_index += 1

        return all_results


class LOGIC_MINIMIZER_CVL(SOLVER_CVL):
    """
    The logic minimizer to be (automatically) called by CiVerLy, to minimize
    boolean formulas and therefore to simplify MILP or SAT models.
    Of course, CiVerLy does not implement any logic minimizer but simply
    calls the corresponding logic minimizer externally.

    Supported minimizers:

        - Espresso: Used throughout the literature for this purpose.
          Freely available on https://github.com/classabbyamp/espresso-logic

    """
    def __init__(self):
        super().__init__()


class GUROBI_CVL(MILP_SOLVER_CVL):
    def __init__(self):
        super().__init__()
        self.name = "Gurobi"
        self.timeout_string = r"Time limit reached"

    def invoke(self, input_file, solution_file,
              log_file=None, time_limit=None):
        r"""Invoke Gurobi solver via shell."""
        super().invoke(
            input_file, solution_file, log_file, time_limit
        )
        command = [
            "gurobi_cl", f"ResultFile={solution_file}",
            str(input_file)
        ]
        if time_limit is not None:
            command.insert(2, f"TimeLimit={time_limit}")
            
        if log_file is not None:
            command.insert(2, f"LogFile={log_file}")

        with suppress_output():
            process = subprocess.Popen(command)
            errno = process.wait()

        if errno != 0:
            self.status = SOLVING_STATUS.ERROR

        if time_limit is not None:
            # check if the solver reported a time out by checking the log file
            # for an according string
            with open(log_file, 'r') as file:
                content = file.read()
            if re.search(self.timeout_string, content, re.MULTILINE):
                self.status = SOLVING_STATUS.TIMEOUT

        if self.status != SOLVING_STATUS.SUCCESS:
            raise SolverException(self.status)
        return

    def get_objective_bounds(self, log_file):
        """
        Extract the bounds on the objective value from the log of an MILP solver.

        This function shall be used when the MILP solver exceeds the given timeout.

        INPUT:

            - ``log_file``-- name of the log file
        """
        assert isinstance(log_file, Path)

        regexp = r'Best objective (\S+), best bound (\S+), gap'

        with open(log_file, 'r') as file:
            content = file.read()

        hit = re.search(regexp, content, re.MULTILINE)
        if hit:
            upper_bound = _float_or_int(hit.group(1))
            lower_bound = _float_or_int(hit.group(2))
            return lower_bound, upper_bound

        warnings.warn(f"No objective bounds found in {log_file}")
        return None, None

    def process_solution_file(self, solution_file_name):
        """
        Parse a solution generated by Gurobi.

        INPUT:

            - ``solution_file_name``-- name of the file containing a solution

        OUTPUT: The processed ``results`` and ``objective_value``.
        """
        assert isinstance(solution_file_name, Path)

        with open(solution_file_name, "r") as f:
            file_content = f.read().split("\n")

        def __string_to_int_gurobi(str):
            """
            Remove rounding errors.

            Solution values can deviate up to 1e-5 from integer solutions, see
            https://support.gurobi.com/hc/en-us/articles/360012237872-Why-does-Gurobi-sometimes-return-non-integral-values-for-integer-variables
            """
            try:
                return int(str)
            except ValueError:
                value_float = float(str)
                value_int = int(round(value_float))
                if abs(value_float - value_int) < 1e-5:
                    return value_int
                raise ValueError(f"Deviation from integer to high: {str}")
        assert file_content != [''], "The model is UNSAT"

        objective_value = file_content[0][file_content[0].index('=')+2:]
        objective_value = _float_or_int(objective_value)
        results = {}
        for line in file_content[1:-1]:
            name = line[:line.index(" ")]
            value = __string_to_int_gurobi(line[line.index(" ")+1:])
            results[name] = value
        return _to_dict(results), objective_value


    def solve_multiple(self, model_options, cipher=None, time_limit=None):
        r"""
        Find up to *n* optimal solutions using Gurobi's solution pool.

        A single Gurobi invocation with ``PoolSearchMode=2`` and ``PoolGap=0``
        finds the optimum and then systematically enumerates additional
        solutions of equal quality, writing each to a numbered ``.sol`` file.

        Gurobi pool parameters used:

        - ``PoolSolutions=n``  – keep at most *n* solutions.
        - ``PoolSearchMode=2`` – systematically enumerate pool solutions.
        - ``PoolGap=0``        – only accept solutions matching the optimum.
        - ``SolFiles=<prefix>``– write pool solutions as
          ``<prefix>0.sol``, ``<prefix>1.sol``, …

        Returns a list of ``(results_dict, objective_value)`` pairs
        (at most *n* entries).
        """

        def solutionpooljson_to_solfiles(json_file_name, solution_file):
            """
            The optimal solutions in the Gurobi solution pool can only be retrieved
            in form of a JSON file. In order to make the program flow coherent
            to the other solvers, write each solution into a new .sol file.
            """
            with open(json_file_name, 'r') as f:
                data = json.load(f)

            num_solutions = data['SolutionInfo']['SolCount']

            for sol_idx in range(num_solutions):
                obj_val = data['SolutionInfo']['PoolNObjVal'][sol_idx]
                
                sol_file = (
                    solution_file.parent
                    / f"{solution_file.stem}_{sol_idx}.sol"
                )

                with open(sol_file, 'w') as f:
                    f.write(f"# Objective value = {obj_val}\n")
                    
                    for var in data['Vars']:
                        var_name = var['VarName']
                        var_value = var['PoolNX'][sol_idx]
                        f.write(f"{var_name} {var_value}\n")
            return


        input_file  = model_options.path / (cipher.name + ".mps")
        solution_file = model_options.path / (cipher.name + ".sol")
        assert isinstance(input_file, Path)
        assert isinstance(solution_file, Path)

        n = model_options.number_of_solutions

        parent = solution_file.parent
        stem = solution_file.stem
        log_file = parent / f"{stem}_{self.name}.log"
        json_file_name = parent / f"{stem}_pool.json"
        command = [
            "gurobi_cl",
            "PoolSearchMode=2",
            f"LogFile={log_file}",
            f"PoolSolutions={n}",
            "JSONSolDetail=1",
            f"ResultFile={json_file_name}",
            str(input_file)
        ]

        if time_limit is not None:
            command.insert(2, f"TimeLimit={time_limit}")

        with suppress_output():
            process = subprocess.Popen(command)
            errno = process.wait()

        if errno != 0:
            self.status = SOLVING_STATUS.ERROR

        if log_file.exists():
            with open(log_file, 'r') as file:
                if re.search(self.timeout_string, file.read(), re.MULTILINE):
                    self.status = SOLVING_STATUS.TIMEOUT

        if self.status != SOLVING_STATUS.SUCCESS:
            raise SolverException(self.status)
        
        # convert to seperate .sol files
        solutionpooljson_to_solfiles(
            json_file_name=json_file_name, solution_file=solution_file
        )

        results = []
        for i in range(n):
            sol_file = (
                solution_file.parent
                / f"{solution_file.stem}_{i}.sol"
            )
            if not sol_file.exists():
                print(f"{sol_file} doesnt exist")
                continue
            try:
                results.append(self.process_solution_file(sol_file))
            except (AssertionError, ValueError):
                print(f"process solution file failed for {sol_file}")
                continue

        # Gurobi always writes the best solution to ResultFile; use as fallback
        if not results and solution_file.exists():
            results.append(self.process_solution_file(solution_file))

        return results


class SCIP_CVL(MILP_SOLVER_CVL):
    def __init__(self):
        super().__init__()
        self.name = "SCIP"
        self.timeout_string = r"time limit reached"

    def invoke(self, input_file, solution_file,
              log_file=None, time_limit=None):
        r"""Invoke SCIP solver via shell."""
        super().invoke(
            input_file, solution_file, log_file, time_limit
        )
        if time_limit is not None:
            with open('scip_settings.set', 'w') as f:
                f.write(f"write/printzeros = TRUE\nlimits/time = {time_limit}")
        else:
            with open('scip_settings.set', 'w') as f:
                f.write('write/printzeros = TRUE')
        command = [
            "scip", "-c",
            (
                f"read {input_file} "
                "optimize write solution "
                f"{solution_file} "
                "quit"
            ),
            "-s", "scip_settings.set",
        ]
        # only add -l flag when log_file is set
        if log_file is not None:
            command += ["-l", str(log_file)]

        with suppress_output():
            process = subprocess.Popen(command)
            errno = process.wait()

        if errno != 0:
            self.status = SOLVING_STATUS.ERROR

        if time_limit is not None:
            # check if the solver reported a time out by checking the log file
            # for an according string
            with open(log_file, 'r') as file:
                content = file.read()
            if re.search(self.timeout_string, content, re.MULTILINE):
                self.status = SOLVING_STATUS.TIMEOUT

        # clean up
        Path("scip_settings.set").unlink(missing_ok=True)

        return

    def get_objective_bounds(self, log_file):
        """
        Extract the bounds on the objective value from
        the log file of a MILP solver.

        This function shall be used when the MILP solver
        exceeds the given timeout.

        INPUT:

            - ``log_file``-- name of the log file

        """
        assert isinstance(log_file, Path)
        regexp = r'Primal Bound\s*:\s*(\S+).*\nDual Bound\s*:\s*(\S+).*'

        with open(log_file, 'r') as file:
            content = file.read()

        hit = re.search(regexp, content, re.MULTILINE)
        if hit:
            upper_bound = _float_or_int(hit.group(1))
            lower_bound = _float_or_int(hit.group(2))
            return lower_bound, upper_bound

        warnings.warn(f"No objective bounds found in {log_file}")
        return None, None

    def process_solution_file(self, solution_file_name):
        """
        Parse a solution generated by SCIP.

        INPUT:

            - ``solution_file_name``-- name of the file containing a solution


        OUTPUT: The processed ``results`` and ``objective_value``.
        """
        assert isinstance(solution_file_name, Path)

        with open(solution_file_name, "r") as f:
            file_content = f.read().split("\n")

        if any(["infeasible" in line for line in file_content[:10]]):
            raise ValueError("There is no solution found!")
        results = {}
        objective_value = file_content[1].strip(" ")
        objective_value = objective_value[objective_value.index(":")+1:]
        objective_value = _float_or_int(objective_value)
        for line in file_content[2:-1]:
            line = line[:line.index("(")].replace(" ", "")
            value = int(round(float(line[line.index("]")+1:])))
            name = line[:line.index("]")+1]
            results[name] = value

        return _to_dict(results), objective_value


class GLPK_CVL(MILP_SOLVER_CVL):
    def __init__(self):
        super().__init__()
        self.name = "GLPK"
        self.timeout_string = r"TIME LIMIT EXCEEDED"

    def invoke(self, input_file, solution_file,
              log_file=None, time_limit=None):
        r"""Invoke GLPK solver via shell."""
        super().invoke(
            input_file, solution_file, log_file, time_limit
        )
        command = [
            "glpsol", str(input_file),
            "-o", str(solution_file)
        ]
        # only add --log flag when log_file is set
        if log_file is not None:
            command += ["--log", str(log_file)]

        if time_limit is not None:
            command.insert(2, "--tmlim")
            command.insert(3, str(time_limit))

        with suppress_output():
            process = subprocess.Popen(command)
            errno = process.wait()

        if errno != 0:
            self.status = SOLVING_STATUS.ERROR

        if time_limit is not None:
            # check if the solver reported a time out by checking the log file
            # for an according string
            with open(log_file, 'r') as file:
                content = file.read()
            if re.search(self.timeout_string, content, re.MULTILINE):
                self.status = SOLVING_STATUS.TIMEOUT

        return

    def get_objective_bounds(self, log_file):
        """
        Extract the bounds on the objective value from the log of an MILP solver.

        This function shall be used when the MILP solver exceeds the given timeout.

        INPUT:

            - ``log_file``-- name of the log file

        """
        assert isinstance(log_file, Path)
        regexp = r'.*mip\s*=\s*(\S+)\s*>=\s*(\S+).*'

        with open(log_file, 'r') as file:
            content = file.read()

        hit = re.search(regexp, content, re.MULTILINE)
        if hit:
            upper_bound = _float_or_int(hit.group(1))
            lower_bound = _float_or_int(hit.group(2))
            return lower_bound, upper_bound

        warnings.warn(f"No objective bounds found in {log_file}")
        return None, None

    def process_solution_file(self, solution_file_name):
        """
        Parse a solution generated by GLPK.

        INPUT:

            - ``solution_file_name``-- name of the file containing a solution

        OUTPUT: The processed ``results`` and ``objective_value``.
        """
        assert isinstance(solution_file_name, Path)

        with open(solution_file_name, "r") as f:
            file_content = f.read().split("\n")

        if any(["INFEASIBLE" in line for line in file_content[-10:]]):
            raise ValueError("There is no solution found!")

        L, R = file_content[5].index("= ")+2, file_content[5].index("(")
        objective_value = _float_or_int(file_content[5][L:R])

        ind_start, ind_end = None, None
        bs, be = False, False

        # Cut off unnecessary lines
        for i_line, line in enumerate(file_content):
            if "No. Column name" in line:
                ind_start = i_line
                bs = True
            if "Integer feasibility conditions" in line:
                ind_end = i_line
                be = True
            if bs and be:
                break
        file_content = file_content[ind_start+2:ind_end]

        file_content = [
            line.replace(" ", "").replace("*", "")[:-2]
            for line in file_content
        ][:-1]
        file_content = [
            line[re.search(r'[A-Za-z]', line).start():]
            for line in file_content
        ]
        file_content = [line.replace(" ", "") for line in file_content]

        results = {}
        for line in file_content:
            i = line.index("]")
            name = line[:i+1]
            value = line[i+1:i+2]
            results[name] = value
        return _to_dict(results), objective_value


class CRYPTOMINISAT_CVL(SAT_SOLVER_CVL):
    def __init__(self):
        super().__init__()
        self.name = "CryptoMiniSat"

    def invoke(self, input_file, solution_file,
              log_file=None, time_limit=None):
        r"""Invoke CryptoMiniSat solver via shell."""
        super().invoke(
            input_file, solution_file, log_file, time_limit
        )
        command = [
            "cryptominisat5",
            "--presimp", "1",
            "--dumpresult", solution_file,
            input_file
        ]
        if time_limit is not None:
            command.insert(1, "--maxtime")
            command.insert(2, str(time_limit))

        if log_file is not None:
            self.redirect_stdout = open(log_file, 'a')

        with suppress_output():
            process = subprocess.Popen(
                command, stdout=self.redirect_stdout,
                stderr=self.redirect_stdout
            )
            errno = process.wait()

        if log_file is not None:
            self.redirect_stdout.close()

        if errno != 0:
            # 10: SAT, 20: UNSAT
            if errno in [10, 20]:
                pass
            elif errno == 15:
                self.status = SOLVING_STATUS.TIMEOUT
            else:
                self.status = SOLVING_STATUS.ERROR

        return

    def process_solution_file(self, solution_file_name):
        """
        Parse '.sat' files and recover the variable assignments as well as the
        objective value.

        INPUT:

            - ``solution_file_name``-- name of the file containing a solution

        OUTPUT: The processed ``results`` and ``objective_value``.

        .. NOTE::

            CiVerLy augments the standard file format convention for SAT output
            files. Typically the first line holds the string 'SAT' or 'UNSAT',
            while the variable assignments are given in the second line, in form of
            the **sign** of the corresponding integer. Additionally, CiVerLy
            writes the objective value into the second line, as an integer, which
            is non-standard.
        """
        assert isinstance(solution_file_name, Path)

        with open(solution_file_name, "r") as f:
            file_content = f.read().split("\n")

        if "UNSAT" in file_content[0]:
            raise AssertionError("The model is UNSAT")

        def __get_val(var):
            if int(var) < 0:
                return 0
            elif int(var) > 0:
                return 1
            else:
                raise AssertionError("Encountered 0 while parsing .sat")

        results = file_content[1].split(" ")[:-1]
        results = {abs(int(var)): __get_val(var) for var in results}
        objective_value = _float_or_int(file_content[2])

        return results, objective_value


class CADICAL_CVL(SAT_SOLVER_CVL):
    def __init__(self):
        super().__init__()
        self.name = "CaDiCal"

    def invoke(self, input_file, solution_file,
              log_file=None, time_limit=None):
        r"""Invoke CaDiCal solver via shell."""
        super().invoke(
            input_file, solution_file, log_file, time_limit
        )
        command = [
            "cadical",
            str(input_file),
            "-P1", # preprocess for 1 round
            "--sat",
            "-w", str(solution_file)
        ]
        if time_limit is not None:
            command.insert(2, "-t")
            command.insert(3, str(time_limit))

        if log_file is not None:
            self.redirect_stdout = open(log_file, 'a')

        with suppress_output():
            process = subprocess.Popen(
                command, stdout=self.redirect_stdout,
                stderr=self.redirect_stdout
            )
            errno = process.wait()

        if log_file is not None:
            self.redirect_stdout.close()

        if errno != 0:
            # 10: SAT, 20: UNSAT
            if errno in [10, 20]:
                pass
            else:
                self.status = SOLVING_STATUS.ERROR

        # if there was no error but there is no solution, we conclude that
        # there was a time out
        if self.status == SOLVING_STATUS.SUCCESS:
            with open(solution_file, 'r') as file:
                line = file.readline().strip("\n")
            if line == "c UNKNOWN":
                self.status = SOLVING_STATUS.TIMEOUT

        return

    def process_solution_file(self, solution_file_name):
        """
        Parse a solution generated by CaDiCal.

        INPUT:

            - ``solution_file_name``-- name of the file containing a solution

        OUTPUT: The processed ``results`` and ``objective_value``.
        """
        assert isinstance(solution_file_name, Path)

        with open(solution_file_name, "r") as f:
            file_content = f.read().split("\n")

        if "UNSATISFIABLE" in file_content[0]:
            raise AssertionError("The model is UNSAT")

        file_content = [
            line[2:] if len(line) > 0 and line[0] in ["v", "s"] else line
            for line in file_content
        ]
        joined = ' '.join(file_content[1:-2])
        file_content = [file_content[0], joined, file_content[-2]]

        def __get_val(var):
            if int(var) < 0:
                return 0
            elif int(var) > 0:
                return 1
            else:
                raise AssertionError("Encountered 0 while parsing .sat")

        results = file_content[1].split(" ")[:-1]
        results = {abs(int(var)): __get_val(var) for var in results}
        objective_value = _float_or_int(file_content[2])

        return results, objective_value


class ESPRESSO_CVL(LOGIC_MINIMIZER_CVL):
    def __init__(self):
        super().__init__()
        self.name = "Espresso"

    def invoke(self, input_file, solution_file,
               log_file=None, time_limit=None):
        r"""Invoke Espresso logic minimizer via shell."""
        super().invoke(
            input_file, solution_file,
            log_file=None, time_limit=None
        )
        command = [
            "espresso",
            "-epos",
            str(input_file)
        ]

        self.redirect_stdout = open(solution_file, 'a')

        # with suppress_output():
        if True:
            process = subprocess.Popen(
                command, stdout=self.redirect_stdout,
                stderr=self.redirect_stdout
            )
            errno = process.wait()

        self.redirect_stdout.close()

        # failure: errno 1
        if errno != 0:
            self.status = SOLVING_STATUS.ERROR

        return


class NO_MILP_SOLVER_CVL(MILP_SOLVER_CVL):
    def solve(self, input_file, solution_file, time_limit=None):
        raise NoSolverWarning()

    def solve_multiple(self, model_options, cipher=None, time_limit=None):
        raise NoSolverWarning()

    def process_solution_file(self, solution_file_name):
        """
        Internal helper method to process the solution file.

        INPUT:

            - ``solution_file_name``-- name of the file containing a solution
            - ``solver`` -- the used solver, see
            :class:`civerly.model_options.SOLVER`

        OUTPUT: The processed ``results`` and ``objective_value``.
        """
        assert isinstance(solution_file_name, Path)

        with open(solution_file_name, "r") as f:
            file_content = f.read().split("\n")

        # try to guess the solver
        if "# Objective value" in file_content[0]:
            return GUROBI_CVL().process_solution_file(solution_file_name)
        elif "Problem:" in file_content[0] and "Rows:" in file_content[1]:
            return GLPK_CVL().process_solution_file(solution_file_name)
        elif "solution status" in file_content[0]:
            return SCIP_CVL().process_solution_file(solution_file_name)
        else:
            raise ValueError("Unknown solution format")


class NO_SAT_SOLVER_CVL(SAT_SOLVER_CVL):
    def solve(self, input_file, solution_file, model_options,
              time_limit=None):
        """
        If no solver is selected, generate all cnf's in solve_range
        and let user solve them externally.
        """
        assert isinstance(input_file, Path)
        assert isinstance(solution_file, Path)

        # shorten variable name
        pr = model_options.sat_precision

        def __get_sum_arr():
            r"""
            Implicit helper function to read and extract the sum_arr from the
            corresponding json file.
            """
            sum_arr_file = input_file.parent / f"{input_file.stem}sum.json"
            with open(sum_arr_file, 'r') as f:
                file_content = json.load(f)

                # Scale all weights by 10**sat_precision
                # (and normalize again later)
                sum_arr = [
                    (weight, var)
                    for weight, var in file_content
                ]
            return sum_arr

        # scale W_MIN, W_MAX too
        W_MIN = int(model_options.solve_range[0] * 10**pr)
        W_MAX = int(model_options.solve_range[1] * 10**pr)

        for w in range(W_MIN, W_MAX):
            sat = DIMACS()
            sat.read(str(input_file))

            sat_constraining_prob = _generate_constraints_sum_leq_int_LS24(
                sat,
                __get_sum_arr(),
                w
            )

            # temporary files with encoded weight w
            name = f"{input_file.stem}_obj{w/10**pr}"
            tmp_cnf_file_name = input_file.parent / f"{name}.cnf"
            sat_constraining_prob.write(tmp_cnf_file_name)
        return

    def process_solution_file(self, solution_file_name):
        """
        Internal helper method to process the solution file.

        INPUT:

            - ``solution_file_name``-- name of the file containing a solution
            - ``solver`` -- the used solver, see
            :class:`civerly.model_options.SOLVER`

        OUTPUT: The processed ``results`` and ``objective_value``.
        """
        assert isinstance(solution_file_name, Path)

        with open(solution_file_name, "r") as f:
            file_content = f.read().split("\n")

        # try to guess the solver
        if "SATISFIABLE" in file_content[0]:  # also catches UNSATISFIABLE
            return CADICAL_CVL().process_solution_file(solution_file_name)
        elif "SAT" in file_content[0]:  # also catches UNSAT
            return CRYPTOMINISAT_CVL().process_solution_file(solution_file_name)
        else:
            raise ValueError("Unknown solution format")

    def solve_multiple(self, model_options, cipher=None, time_limit=None):
        raise NoSolverWarning()


class NO_LOGIC_MINIMIZER_CVL(LOGIC_MINIMIZER_CVL):
    def __init__(self):
        super().__init__()

    def solve(self, input_file, solution_file):
        raise NoSolverWarning()


class SOLVING_STATUS(Enum):
    """Indicate if solving was successful or what went wrong."""

    SUCCESS = 1
    TIMEOUT = 2
    ERROR = 3


class NoSolverWarning(Warning):
    r"""
    Warning which will be thrown whenever :meth:`analyse` is called with
    `model_options.solver = None`.

    EXAMPLES::

        sage: from civerly.model_options import *
        sage: from civerly.util import suppress_output
        sage: from civerly.cipher_implementations.aes import AES_CVL
        sage: import tempfile
        sage: aes = AES_CVL(6)
        sage: with tempfile.TemporaryDirectory() as tmpdir:
        ....:   model_options = MODEL_OPTIONS(
        ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
        ....:     optimization=OPTIMIZATION.MILP,
        ....:     granularity=GRANULARITY.WORDWISE,
        ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.GENERALIZED_WORDWISE,
        ....:     milp_solver=None,
        ....:     sat_solver=None,
        ....:     path=Path(tmpdir))
        ....:   with suppress_output():
        ....:     aes.analyse(model_options)
        Traceback (most recent call last):
        ...
        NoSolverWarning: No solver has been selected.
        CiVerLy will return without solving.


    """
    def __init__(self):
        super().__init__(
            "No solver has been selected. "
            "CiVerLy will return without solving."
        )


class SolverException(Exception):
    def __init__(self, e):
        if e == SOLVING_STATUS.TIMEOUT:
            super().__init__("Solver / Minimizer timed out.")
        elif e == SOLVING_STATUS.ERROR:
            super().__init__("Solver / Minimizer raised an external error.")
