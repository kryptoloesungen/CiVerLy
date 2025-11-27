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

from civerly.model_options import SOLVER, InvalidModelOptionException
from sage.sat.solvers.dimacs import DIMACS
from civerly.util import _generate_constraints_sum_leq_int_LS24
from civerly.util import suppress_output


class SOLVING_STATUS(Enum):
    """Indicate if solving was successful or what went wrong."""

    SUCCESS = 1
    TIMEOUT = 2
    ERROR = 3


def solve(input_file_name, output_file_name, solver, time_limit=None,
          log_file_name=None):
    """
    Solve the given MILP or SAT instance externally.

    INPUT:

        - ``input_file_name``-- path to the file containing the MILP or SAT

        - ``output_file_name``-- path of the file the solution is written to

        - ``solver`` -- see :class:`civerly.model_options.SOLVER`

        - ``time_limit``-- integer (default ``None``); time limit in seconds

        - ``log_file_name``-- path to the solver's log file. Default based on
          ``output_file_name`` and ``solver``.

    OUTPUT:

        - Status, see :class:`civerly.solvers.SOLVING_STATUS`. Further, upon
          successful execution either a ``.sol`` or a ``.sat`` file is created,
          depending on ``solver``. The file will contain the solution, if one
          is found.

    .. NOTE::

        This method is implemented for convenience in case a solver is
        installed on the same machine as CiVerLy.
    """
    assert isinstance(input_file_name, Path)
    assert isinstance(output_file_name, Path)
    assert isinstance(solver, SOLVER)

    # overwritten for solvers not supporting log files
    redirect_stdout = None

    # default return value
    status = SOLVING_STATUS.SUCCESS

    # default log file
    if log_file_name is None:
        parent_dir = output_file_name.parent
        name = f"{output_file_name.stem}_{solver.name}"
        suffix = ".log"
        log_file_name = parent_dir / (name + suffix)
    else:
        assert isinstance(log_file_name, Path)

    # you can disable a solver by setting an environment variable
    # with this we simulate that a solver is not installed albeit it is
    # i.e. this is used for testing only
    ENV_DISABLE_PREFIX = "CIVERLY_DISABLE_"
    if ENV_DISABLE_PREFIX+solver.name in os.environ:
        raise ValueError(
            f"{solver.name} was disabled by setting environment variable "
            f"{ENV_DISABLE_PREFIX+solver.name}"
        )
    # ------------------------------------------------------
    if solver == SOLVER.GUROBI:
        command = [
            "gurobi_cl",
            f"ResultFile={output_file_name}",
            f"LogFile={log_file_name}",
            str(input_file_name)
        ]
        if time_limit is not None:
            command.insert(2, f"TimeLimit={time_limit}")
    # ------------------------------------------------------
    elif solver == SOLVER.GLPK:
        command = [
            "glpsol",
            str(input_file_name),
            "--log", str(log_file_name),
            "-o", str(output_file_name)
        ]
        if time_limit is not None:
            command.insert(2, "--tmlim")
            command.insert(3, str(time_limit))
    # ------------------------------------------------------
    elif solver == SOLVER.SCIP:
        if time_limit is not None:
            with open('scip_settings.set', 'w') as f:
                f.write(f"write/printzeros = TRUE\nlimits/time = {time_limit}")
        else:
            with open('scip_settings.set', 'w') as f:
                f.write('write/printzeros = TRUE')
        command = [
            "scip",
            "-c",
            (
                f"read {input_file_name} "
                "optimize write solution "
                f"{output_file_name} "
                "quit"
            ),
            "-s", "scip_settings.set",
            "-l", str(log_file_name)
        ]
    # ------------------------------------------------------
    elif solver == SOLVER.CRYPTOMINISAT:
        command = [
            "cryptominisat5",
            "--presimp", "1",
            "--dumpresult", output_file_name,
            input_file_name
        ]
        if time_limit is not None:
            command.insert(1, "--maxtime")
            command.insert(2, str(time_limit))
        redirect_stdout = open(log_file_name, 'a')
    # ------------------------------------------------------
    elif solver == SOLVER.CADICAL:
        command = [
            "cadical",
            str(input_file_name),
            "--flush",  # --flush to flush redundant clauses
            "--sat",
            "-w", str(output_file_name)
        ]
        if time_limit is not None:
            command.insert(2, "-t")
            command.insert(3, str(time_limit))
        redirect_stdout = open(log_file_name, 'a')
    # ------------------------------------------------------
    else:
        raise InvalidModelOptionException(solver, SOLVER)

    with suppress_output():
        process = subprocess.Popen(command, stdout=redirect_stdout,
                                   stderr=redirect_stdout)
        errno = process.wait()

    if redirect_stdout is not None:
        redirect_stdout.close()

    if (errno != 0):
        if solver == SOLVER.CRYPTOMINISAT:
            # 10: SAT, 20: UNSAT
            if errno in [10, 20]:
                pass
            elif errno == 15:
                status = SOLVING_STATUS.TIMEOUT
            else:
                status = SOLVING_STATUS.ERROR
        elif solver == SOLVER.CADICAL:
            # 10: SAT, 20: UNSAT
            if errno in [10, 20]:
                pass
            else:
                status = SOLVING_STATUS.ERROR
        else:
            status = SOLVING_STATUS.ERROR

    if time_limit is not None:
        # check if the solver reported a time out by checking the log file for
        # an according string
        if solver == SOLVER.GUROBI:
            regexp = r"Time limit reached"
        elif solver == SOLVER.GLPK:
            regexp = r"TIME LIMIT EXCEEDED"
        elif solver == SOLVER.SCIP:
            regexp = r"time limit reached"
        # CRYPTOMINISAT: see errno above
        # CADICAL: see below
        else:
            regexp = r"(?!)"  # never matches

        with open(log_file_name, 'r') as file:
            content = file.read()
        if re.search(regexp, content, re.MULTILINE):
            status = SOLVING_STATUS.TIMEOUT

    if solver == SOLVER.CADICAL:
        # if there was no error but there is no solution, we conclude that
        # there was a time out
        if status == SOLVING_STATUS.SUCCESS:
            with open(output_file_name, 'r') as file:
                line = file.readline().strip("\n")
            if line == "c UNKNOWN":
                status = SOLVING_STATUS.TIMEOUT

    # clean up
    if solver == SOLVER.SCIP:
        Path("scip_settings.set").unlink(missing_ok=True)

    # be silent on success
    return status if status != SOLVING_STATUS.SUCCESS else None


def optimize_sat(cnf_file_name, sat_file_name, model_options,
                 time_limit=None, benchmark=False):
    """
    Repeatedly solve SAT to determine the lowest possible weight.

    Given a SAT with its corresponding ``sum_arr``, this method applies a
    binary search to determine the lowest weight ``w`` for which this SAT is
    solvable and solves it.

    INPUT:

        - ``cnf_file_name``-- path to the file containing the SAT

        - ``sat_file_name``-- path to the file the solution is written to

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
    assert isinstance(cnf_file_name, Path)
    assert isinstance(sat_file_name, Path)

    if time_limit is not None:
        end_time = int(time.time()+time_limit)

    # shorten variable name
    pr = model_options.sat_precision

    benchmarks = []

    def __get_sum_arr():
        r"""
        Implicit helper function to read and extract the sum_arr from the
        corresponding json file.
        """
        sum_arr_file = cnf_file_name.parent / f"{cnf_file_name.stem}sum.json"
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
    # If no solver is selected, generate all cnf's in solve_range
    # and let user solve them externally.
    # ---------------------------------------------------------------
    if model_options.solver is None:
        for w in range(W_MIN, W_MAX):
            sat = DIMACS()
            sat.read(str(cnf_file_name))

            sat_constraining_prob = _generate_constraints_sum_leq_int_LS24(
                sat,
                __get_sum_arr(),
                w
            )

            # temporary files with encoded weight w
            name = f"{cnf_file_name.stem}_obj{
                w/10**pr
            }"
            tmp_cnf_file_name = cnf_file_name.parent / f"{name}.cnf"
            tmp_sat_file_name = cnf_file_name.parent / f"{name}.sat"
            sat_constraining_prob.write(tmp_cnf_file_name)
        return
    # ---------------------------------------------------------------

    ALL_SAT, ALL_UNSAT = True, True
    # ---------------------------------------------------------------
    while W_MAX > W_MIN or ALL_UNSAT or ALL_SAT:
        w = (W_MAX + W_MIN) // 2

        # will be appended to benchmarks
        row = {"bound": w}
        row["W_MIN"] = W_MIN
        row["W_MAX"] = W_MAX

        sat = DIMACS()
        sat.read(str(cnf_file_name))

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
        name = f"{cnf_file_name.stem}_obj{w}"
        tmp_cnf_file_name = cnf_file_name.parent / f"{name}.cnf"
        tmp_sat_file_name = cnf_file_name.parent / f"{name}.sat"
        sat_constraining_prob.write(tmp_cnf_file_name)
        if time_limit is not None:
            tmp_time_limit = end_time - int(time.time())
            if tmp_time_limit < 0:
                return SOLVING_STATUS.TIMEOUT, (W_MIN/10**pr, W_MAX/10**pr)
        else:
            tmp_time_limit = None

        start = time.time()
        status = solve(
            tmp_cnf_file_name,
            tmp_sat_file_name,
            model_options.solver,
            tmp_time_limit
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
    name = f"{cnf_file_name.stem}_obj{W_MIN}"
    tmp_cnf_file_name = cnf_file_name.parent / f"{name}.cnf"
    tmp_sat_file_name = cnf_file_name.parent / f"{name}.sat"
    shutil.copyfile(tmp_cnf_file_name, cnf_file_name)
    shutil.copyfile(tmp_sat_file_name, sat_file_name)

    # write optimization value into the sat file
    with open(sat_file_name, 'a') as f:
        f.write(str(float(W_MIN/10**pr))+"\n")

    if benchmark:
        return benchmarks

    if pr == 0:
        return int(W_MIN)
    return float(W_MIN/10**pr)


def _float_or_int(value):
    """
    Cast `value` to float or int if possible.

    EXAMPLES::

        sage: from civerly.solvers import _float_or_int
        sage: _float_or_int(42.0)
        42
        sage: _float_or_int(42.5)
        42.5
        sage: _float_or_int("42.000")
        42
        sage: _float_or_int("42.001")
        42.001
        sage: _float_or_int("3.415037499300e+00")
        3.4150374993
    """
    value = float(value)
    if value.is_integer() or abs(value - int(round(value))) < 1e-8:
        value = int(round(value))
    return value


def get_objective_bounds(log_file_name, solver):
    """
    Extract the bounds on the objective value from the log of an MILP solver.

    This function shall be used when the MILP solver exceeds the given timeout.

    INPUT:

        - ``log_file_name``-- name of the log file
        - ``solver`` -- the used solver, see
          :class:`civerly.model_options.SOLVER`
    """
    assert isinstance(log_file_name, Path)

    if solver == SOLVER.GUROBI:
        regexp = r'Best objective (\S+), best bound (\S+), gap'
    elif solver == SOLVER.GLPK:
        regexp = r'.*mip\s*=\s*(\S+)\s*>=\s*(\S+).*'
    elif solver == SOLVER.SCIP:
        regexp = r'Primal Bound\s*:\s*(\S+).*\nDual Bound\s*:\s*(\S+).*'
    else:
        raise InvalidModelOptionException(solver, SOLVER)

    with open(log_file_name, 'r') as file:
        content = file.read()

    hit = re.search(regexp, content, re.MULTILINE)
    if hit:
        upper_bound = _float_or_int(hit.group(1))
        lower_bound = _float_or_int(hit.group(2))
        return lower_bound, upper_bound

    warnings.warn(f"No objective bounds found in {log_file_name}")
    return None, None


def get_objective_value(sol_file_name, solver):
    """
    Extract the objective value from the specified solution file.

    INPUT:

        - ``sol_file_name``-- name of the file containing a solution
        - ``solver`` -- the used solver, see
          :class:`civerly.model_options.SOLVER`
    """
    assert isinstance(sol_file_name, Path)
    _, objective_value = _process_solution_file(sol_file_name, solver)
    return objective_value


def _process_solution_file(solution_file_name, solver):
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
    if solver is None:
        if "# Objective value" in file_content[0]:
            solver = SOLVER.GUROBI
        elif "Problem:" in file_content[0] and "Rows:" in file_content[1]:
            solver = SOLVER.GLPK
        elif "solution status" in file_content[0]:
            solver = SOLVER.SCIP
        elif "SATISFIABLE" in file_content[0]:  # also catches UNSATISFIABLE
            solver = SOLVER.CADICAL
        elif "SAT" in file_content[0]:  # also catches UNSAT
            solver = SOLVER.CRYPTOMINISAT
        else:
            raise ValueError("Unknown solution format")

    if solver == SOLVER.GUROBI:
        return __parse_gurobi(file_content)
    elif solver == SOLVER.GLPK:
        return __parse_glpk(file_content)
    elif solver == SOLVER.SCIP:
        return __parse_scip(file_content)
    elif solver == SOLVER.CRYPTOMINISAT:
        return __parse_cryptominisat(file_content)
    elif solver == SOLVER.CADICAL:
        return __parse_cadical(file_content)
    else:
        raise InvalidModelOptionException(solver, SOLVER)


def __parse_cryptominisat(file_content):
    r"""
    Parse '.sat' files and recovers the variable assignments as well as the
    objective value.

    .. NOTE::

        CiVerLy augments the standard file format convention for SAT output
        files. Typically the first line holds the string 'SAT' or 'UNSAT',
        while the variable assignments are given in the second line, in form of
        the **sign** of the corresponding integer. Additionally, CiVerLy
        writes the objective value into the second line, as an integer, which
        is non-standard.
    """
    assert "UNSAT" not in file_content[0], "The model is UNSAT"

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


def __parse_cadical(file_content):
    """Parse a solution generated by CaDiCal."""
    assert "UNSATISFIABLE" not in file_content[0], "The model is UNSAT"

    file_content = [
        line[2:] if len(line) > 0 and line[0] in ["v", "s"] else line
        for line in file_content
    ]
    joined = ' '.join(file_content[1:-2])
    file_content = [file_content[0], joined, file_content[-2]]
    return __parse_cryptominisat(file_content)


def __parse_gurobi(file_content):
    """Parse a solution generated by Gurobi."""
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
    return results, objective_value


def __parse_scip(file_content):
    """Parse a solution generated by SCIP."""
    if not all(["infeasible" not in line for line in file_content[:10]]):
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

    return results, objective_value


def __parse_glpk(file_content):
    """Parse a solution generated by GLPK."""
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
    return results, objective_value


def __parse_other_solver(file_content):
    r"""
    Parse a solution generated by another solver.

    .. NOTE::

       For future development

    It is possible to extend the functionality of CiVerLy by supporting
    additional solvers. For this, a seperate parse function is necessary, which
    handles the ``.sol`` file.

    This parser function is required to take the following input:

    INPUT:

    - ``file_content`` -- A list of strings, which is the result of
      ``f.read().split("\n")`` of the given solution file.

    OUTPUT:

    - ``results`` -- A dictionary of the form { <variable> : <value>, ...}
      which contains the solution values.

    - ``objective_value`` -- integer; Contains the achieved objective value.
    """
    e = "This method is a placeholder for future extensions of CiVerLy!"
    raise NotImplementedError(e)
