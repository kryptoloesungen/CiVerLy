r"""
Util class of CiVerLy

Contains utility functions.

EXAMPLES::


    sage: from civerly.util import int_to_vec, vec_to_int
    sage: int_to_vec(0x1234, 16)
    (0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0)
    sage: int_to_vec(0x1234, 32)
    (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0,
    0, 0, 1, 1, 0, 1, 0, 0)
    sage: type(int_to_vec(0x1234, 32))
    <class 'sage.modules.vector_mod2_dense.Vector_mod2_dense'>
    sage: vec_to_int(int_to_vec(0x1234,16)) == 0x1234
    True
    sage: int_to_vec(0x1234, 12)
    Traceback (most recent call last):
    ...
    ValueError: Input size of 4660 too large (can at most be 4096)

TESTS:

    Verify that temporary directories used in doctests are actually removed
    after cleanup, and that errors during cleanup are raised rather than
    silently suppressed::

        sage: import tempfile, shutil, os
        sage: tmpdir = tempfile.mkdtemp()
        sage: assert os.path.exists(tmpdir)    # directory exists before cleanup
        sage: shutil.rmtree(tmpdir)
        sage: os.path.exists(tmpdir)           # directory is gone after cleanup
        False
        sage: shutil.rmtree(tmpdir)            # raises without ignore_errors
        Traceback (most recent call last):
        ...
        FileNotFoundError: ...

"""

import warnings

import contextlib
import random
import zlib
import sys
import os

from sage.rings.integer_ring import ZZ
from sage.rings.integer import Integer
from sage.rings.finite_rings.finite_field_constructor import GF
from sage.modules.free_module_element import vector
from sage.modules.free_module import VectorSpace
from sage.geometry.polyhedron.constructor import Polyhedron
from sage.sat.solvers.dimacs import DIMACS
from sage.numerical.mip import MixedIntegerLinearProgram

# suppress LazyImport warnings from Polyhedron class
warnings.filterwarnings("ignore", category=UserWarning)


def vec_to_int(input_vec):
    r"""
    Converts a binary vector (see
    ``sage.modules.vector_mod2_dense.Vector_mod2_dense``
    for details) into the corresponding integer.

    INPUT:

        - ``input_vec`` -- Binary vector; Represents the input vector.

    OUTPUT: The integer represented by ``input_vec``.

    EXAMPLES::

        sage: from civerly.util import vec_to_int
        sage: hex(vec_to_int(vector(
        ....:   GF(2),
        ....:   [1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0]
        ....: )))
        '0x4f51a'
    """
    output_num = 0  # convert to Integer
    for i in input_vec:
        output_num <<= 1
        output_num += ZZ(i)
    return output_num


def int_to_vec(input_num, size):
    r"""
    Converts an integer into the corresponding binary vector (see
    ``sage.modules.vector_mod2_dense.Vector_mod2_dense`` for details).

    INPUT:

        - ``input_num`` -- integer; Represents the integer input.

        - ``size`` -- integer; The length of the resulting vector

    OUTPUT: The binary vector representing ``input_num``.

    EXAMPLES::

        sage: from civerly.util import int_to_vec
        sage: int_to_vec(0x12340, 24)
        (0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0,
        1, 0, 0, 0, 0, 0, 0)
        sage: int_to_vec(0x12340, 16)
        Traceback (most recent call last):
        ...
        ValueError: Input size of 74560 too large (can at most be 65536)

    TESTS::

        sage: import random
        sage: from civerly.util import int_to_vec, vec_to_int
        sage: random_num = random.randint(0, (1 << 40) - 1)
        sage: vec_to_int(int_to_vec(random_num, 40)) == random_num
        True
    """
    if input_num >= (1 << size):
        raise ValueError(
            f"Input size of {input_num} too large (can at most be {1 << size})"
        )
    return vector(GF(2), size, ZZ(input_num).digits(2, padto=size)[::-1])


def hw(num):
    r"""
    Return the hamming weight of the integer ``num``.

    sage: from civerly.util import hw
    sage: hw(0x91)
    3
    sage: hw(0xff)
    8
    sage: hw([1, 0, 1, 1])
    Traceback (most recent call last):
    ...
    ValueError: Wrong input type <class 'list'>, must be int-like

    """
    if type(num) in (int, ZZ, Integer):
        return bin(num).count('1')
    else:
        raise ValueError(f"Wrong input type {type(num)}, must be int-like")


def hw_tau(n, tau):
    r"""
    Generate integers of hammingweight ``tau``.

    TESTS::

        sage: from civerly.util import hw_tau
        sage: hw_tau(3, 2)
        [3, 5, 6]
        sage: arr = hw_tau(8, 3)
        sage: len(arr) == binomial(8, 3)
        True
        sage: max(arr) < (1 << 8)
        True

    """
    assert n >= tau
    x = (1 << tau) - 1
    limit = 1 << n
    arr = []
    while x < limit:
        arr.append(x)
        rightmost_one = x & -x
        next_x = x + rightmost_one
        x = (((x ^ next_x) >> 2) // rightmost_one) | next_x
    return arr


def list_of_predecessor_vector_indices(v, num_bits):
    r"""
    Return a list of integers that encode binary vectors preceeding ``v``,
    with the partial order :math:`v \prec w \iff v_i \leq w_i \forall i`.

    TESTS::

        sage: from civerly.util import list_of_predecessor_vector_indices
        sage: vec = vector(GF(2), [1, 1, 1, 0])
        sage: list_of_predecessor_vector_indices(vec, 4)
        [0, 8, 4, 12, 2, 10, 6]
        sage: list_of_predecessor_vector_indices(vec, 5)
        Traceback (most recent call last):
        ...
        AssertionError

    """
    assert num_bits <= len(v)
    set_bit_indices = []
    for i in range(num_bits):
        if v[::-1][i] == 1:
            set_bit_indices.append(i)
    out = []
    for vals in range(1 << len(set_bit_indices)):
        vals_vec = list(int_to_vec(vals, len(set_bit_indices)))
        tmp = 0
        for i in range(len(set_bit_indices)):
            tmp |= int(vals_vec[i]) << set_bit_indices[i]
        out.append(tmp)
    out.remove(vec_to_int(v))
    return out


def translate_sat_clause(VAR, clause):
    r"""
    Given a clause in form of a tuple and an Iterable ``VAR``,
    translate the clause into a clause using the ``VAR`` entries.

    .. NOTE::
        This not only works for SAT clauses, but also to translate SAT
        clauses into MILP constraints.

    EXAMPLE::

        sage: from civerly.util import translate_sat_clause
        sage: VAR = [11, 22, 33, 44, 55]
        sage: clause = (1, -2, 3, -4, -5)
        sage: translate_sat_clause(VAR, clause)
        (11, -22, 33, -44, -55)
        sage: from sage.numerical.mip import MixedIntegerLinearProgram
        sage: milp = MixedIntegerLinearProgram(
        ....:   maximization=False, solver="GLPK"
        ....: )
        sage: VAR_milp = milp.new_variable(name="VAR", binary=True)
        sage: translate_sat_clause(VAR_milp, clause)
        (x_0, -1*x_1, x_2, -1*x_3, -1*x_4)

    """
    return tuple((-1)**((i < 0) & 1) * VAR[abs(i)-1] for i in clause)


def translate_milp_constraint(VAR, constr):
    r"""
    Given a MILP constraint and an Iterable of MILP variables ``VAR`` ,
    translate the constraint into a new constraint using the entries of
    ``VAR``.

    TESTS::

        sage: from civerly.util import translate_milp_constraint
        sage: from sage.numerical.mip import MixedIntegerLinearProgram
        sage: milp = MixedIntegerLinearProgram(
        ....:   maximization=False, solver="GLPK"
        ....: )
        sage: X = milp.new_variable(name="X", binary=True)
        sage: Y = milp.new_variable(name="Y", binary=True)
        sage: constr = (-1*X[0] + 2*X[1] >= X[2])
        sage: milp.add_constraint(constr)
        sage: translate_milp_constraint(Y, milp.constraints()[0])
        -2*x_3 + x_4 + x_5 <= 0
        sage: constr
        x_2 <= -1*x_0 + 2*x_1

    Clearly these are the same constraints up to reordering and up to the
    variable indices. Due to the SageMath's naming of MILP variables, it
    might not be directly clear that x_0, x_1, x_2 do in fact correspond to
    X[0], X[1], X[2] while x_3, x_4, x_5 correspond to Y[0], Y[1], Y[2].

    """
    # the current linear term in the MILP
    summ = sum(
        constr[1][1][j] * VAR[constr[1][0][j]]
        for j in range(len(constr[1][0]))
    )
    if constr[0] is None:
        new_constr = summ <= constr[2]
    elif constr[2] is None:
        new_constr = constr[0] <= summ
    elif constr[0] == constr[2]:
        new_constr = constr[0] == summ
    else:
        new_constr = constr[0] <= summ <= constr[2]
    return new_constr


def _between_brackets(st):
    r"""
    From the given string ``st``, return the integer which is inbetween the
    first pair of squared brackets in this string. This assumes that `st`
    contains such brackets in the first place.

    TESTS::

        sage: from civerly.util import _between_brackets
        sage: _between_brackets("TEST[5812]")
        5812
        sage: _between_brackets("TEST[912]TEST[120]")
        912
        sage: _between_brackets("[TEST]")
        Traceback (most recent call last):
        ...
        ValueError: invalid literal for int() with base 10: 'TEST'

    """
    assert all(bracket in st for bracket in ('[', ']'))
    return int(st[st.index('[') + 1: st.index(']')], 10)


def _before_brackets(st):
    r"""
    From the given string ``st``, return the integer displayed between the
    second char and the first squared open bracket.
    As an example, from "X15[42]", return 15 as int.

    NOTE: We assume ``st`` to have this form, and that the variable name is
    one letter (just "X")!

    TESTS::

        sage: from civerly.util import _before_brackets
        sage: _before_brackets("X921[1284]")
        921
        sage: _before_brackets("T1785[.-")
        1785
        sage: _before_brackets("TEST98[10]")
        Traceback (most recent call last):
        ...
        ValueError: invalid literal for int() with base 10: 'EST98'

    """
    assert '[' in st
    return int(st[1: st.index('[')], 10)


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
    else:
        value = round(value, 10)
    return value


def _generate_constraints_sum_leq_int_LS24(sat, sum_arr, num):
    r"""
    Helper method to implement a sequential counter in SAT, in order to model
    the constraint :math:`sum(arr) \leq num` as a SAT-formula.
    The constraints are given in
    https://link.springer.com/chapter/10.1007/978-3-031-54776-8_14,
    section 3.4.

    .. NOTE::
        There is a typo in this paper, as the sum that we want to bound should
        go from :math:`0 \leq i \leq l-1` instead of :math:`l`.
        Therefore, the last constraint must be
        :math:`\bar{u_{l-1}} \lor \bar{a_{l-2, w-1}}` instead of
        :math:`\bar{u_{l}} \lor \bar{a_{l-1, w-1}}`.

    TESTS::

        sage: # optional - cryptominisat
        sage: from civerly.util import _generate_constraints_sum_leq_int_LS24
        sage: from sage.sat.solvers.dimacs import DIMACS
        sage: from civerly.solvers import *
        sage: from civerly.model_options import *
        sage: import tempfile
        sage: from pathlib import Path
        sage: tmpdir = tempfile.mkdtemp()
        sage: path = Path(tmpdir)
        sage: for NUM_CLAUSES in range(1, 20):
        ....:   sat = DIMACS()
        ....:   for i in range(1, NUM_CLAUSES + 1): sat.add_clause((i,))
        ....:   for bound in range(NUM_CLAUSES + 4):
        ....:       new_sat = _generate_constraints_sum_leq_int_LS24(
        ....:           sat, [(1, cl) for cl in range(1, NUM_CLAUSES+1)], bound
        ....:       )
        ....:       _ = new_sat.write(path / 'constraints.cnf')
        ....:       CRYPTOMINISAT_CVL().invoke(
        ....:           path / 'constraints.cnf',
        ....:           path / 'constraints.sat',
        ....:       )
        ....:       with open(path /'constraints.sat') as f:
        ....:           status = f.readlines()[0].strip('\n')
        ....:           f.close()
        ....:       if status == 'SAT':
        ....:           if bound != NUM_CLAUSES:
        ....:               raise AssertionError(
        ....:                   "The constraints don't assert correct bound!")
        ....:           else: break
        sage: import shutil
        sage: shutil.rmtree(tmpdir)

    If everything works correctly, then a constraint system which requires
    :math:`w` many variables to be SAT only becomes possible to solve if we
    append constraints that bound the weight to at least :math:`w`.
    This is exactly what is checked in the doctests above.


    """
    new_sat = DIMACS()
    for _ in range(sat.nvars()):
        new_sat.var()  # set counter to ``sat.nvars()``
    assert sat.nvars() == new_sat.nvars()

    for clause in sat.clauses():  # copy clauses
        new_sat.add_clause(clause[0])

    # instead of e.g. [(3, 124), (2, 158)], we have [124, 124, 124, 158, 158]
    u = []
    for arr_with_mults in [factor*[entry] for factor, entry in sum_arr]:
        u += arr_with_mults

    L = len(u)

    # special, trivial case for sum_arr with less elements than bound
    if L <= num:
        return new_sat

    # special, trivial case for w = 0
    if num == 0:
        for i in range(L):
            new_sat.add_clause((-u[i], ))
        return new_sat

    # auxilary vars a_{i,j}
    a = [[new_sat.var() for _ in range(num)] for _ in range(L)]

    new_sat.add_clause((-u[0], a[0][0]))
    for j in range(1, num):
        new_sat.add_clause((-a[0][j], ))
    for i in range(1, L-1):
        new_sat.add_clause((-u[i], a[i][0]))
        new_sat.add_clause((-a[i-1][0], a[i][0]))
        for j in range(1, num):
            new_sat.add_clause((-u[i], -a[i-1][j-1], a[i][j]))
            new_sat.add_clause((-a[i-1][j], a[i][j]))
        new_sat.add_clause((-u[i], -a[i-1][num-1]))
    new_sat.add_clause((-u[L-1], -a[L-2][num-1]))

    return new_sat


def _write_espresso_input(posset, esp_file_name, workdir_path):
    r"""
    Helper function of :meth:`_get_clauses_espresso` to write
    the list of clauses generated CiVerLy into a .pla file.

    TESTS::

        sage: from civerly.util import _write_espresso_input
        sage: import tempfile
        sage: from pathlib import Path
        sage: import os
        sage: tmpdir = tempfile.mkdtemp()
        sage: path = Path(tmpdir)
        sage: file_name = "espresso-input-doctest"
        sage: posset = [(0, 0, 0)]
        sage: _write_espresso_input(posset, file_name, path)
        sage: os.path.exists(path / f"{file_name}_in.pla")
        True
        sage: import shutil
        sage: shutil.rmtree(tmpdir)

    """

    # create directory and file
    esp_file_in = workdir_path / f"{esp_file_name}_in.pla"
    workdir_path.mkdir(parents=True, exist_ok=True)

    # create espresso input
    espresso_input = [f'.i {len(posset[0])}', '.o 1']
    for possible_transition in posset:
        espresso_input.append(
            ''.join([str(t) for t in possible_transition]) + ' 1'
        )
    espresso_input.append('.e')
    espresso_input = '\n'.join(espresso_input) + '\n'

    # write to file
    with open(esp_file_in, "w") as f:
        f.write(espresso_input)

    return


def _read_espresso_output(esp_file_out):
    r"""
    Helper function of :meth:`_get_clauses_espresso` to convert
    the output .pla file into a usable list for CiVerLy.

    TESTS::

        sage: from civerly.util import _write_espresso_input
        sage: from civerly.util import _read_espresso_output
        sage: import tempfile
        sage: from pathlib import Path
        sage: import os
        sage: tmpdir = tempfile.mkdtemp()
        sage: path = Path(tmpdir)
        sage: file_name = "espresso-output-doctest"
        sage: posset = [(0, 0, 0), (1, 1, 1)]
        sage: _write_espresso_input(posset, file_name, path)
        sage: assert os.path.exists(path / f"{file_name}_in.pla")
        sage: clauses = _read_espresso_output(path / f"{file_name}_in.pla")
        sage: posset_from_clauses = [
        ....:   tuple((-1)**p[i-1] * i for i in [1, 2, 3])
        ....:   for p in posset
        ....: ]
        sage: clauses == posset_from_clauses
        True
        sage: import shutil
        sage: shutil.rmtree(tmpdir)

    Note that the clauses are not the correct ones describing posset,
    as the flipping via Espresso's `-epos` is missing.
    """

    with open(esp_file_out) as f:
        espresso_output = f.read().splitlines()
    clause_length = int(espresso_output[0].split(" ")[1])

    clauses = []
    for line in espresso_output:
        if line[0] not in ['0', '1', '-']:
            continue  # skip the header lines
        if line[-1] == '1':  # only take the CNF-clauses
            # i+1 to avoid sign errors
            # NOTE: in post-processing, we must subtract -1 again
            clause = tuple(
                (-1)**int(line[i]) * (i + 1)
                for i in range(clause_length)
                if line[i] != '-'
            )
            clauses.append(clause)
    return clauses


def reduction_algorithm_ST17(comp, posset, model_options, PROB=None):
    r"""
    Implements Yosuke Todos and Yu Sasakis Reduction Algorithm
    (https://link.springer.com/chapter/10.1007/978-3-319-69284-5_11),
    which models the problem of choosing a minimal subset of
    MILP-constraints as a MILP itself. Intended to be used internally.
    """
    from civerly.component import SBox_CVL, LinearLayer_CVL
    from civerly.solvers import NO_MILP_SOLVER_CVL

    assert isinstance(comp, (SBox_CVL, LinearLayer_CVL))

    # STEP 1:
    # use sage to generate a convex hull
    convex_hull = Polyhedron(vertices=posset)
    imposset = [
        vector(convex_hull.base_ring(), v)
        for v in VectorSpace(GF(2), convex_hull.ambient_dim())
        if v not in posset
    ]
    R_bar = [[] for _ in range(len(imposset))]
    convex_constraints = convex_hull.inequalities() + convex_hull.equations()

    # STEP 2:
    # generate and solve MILP to minimize number of constraints

    # STEP 2.1:
    # set name of the temporary file in which the reduction milp is stored
    # ------------------------------------------------------------------------
    if isinstance(comp, LinearLayer_CVL):
        file_name = comp.name + str(
            sum([ZZ(i) for i in comp.binary_matrix[0]])
        ) + str(
            sum([ZZ(j) for i in comp.binary_matrix for j in i])
        ) + str(
            sum([ZZ(i) for i in comp.binary_matrix[-1]])
        )
    elif isinstance(comp, SBox_CVL):
        file_name = f"{zlib.crc32(
            "".join([f'{s_entry:x}' for s_entry in comp.S]).encode("utf-8")
        ):x}"
    else:
        raise ValueError(
            "reduction_algorithm_ST17 can only be applied to "
            f"LinearLayer_CVL or SBox_CVL, not to {type(comp)}"
        )
    # ------------------------------------------------------------------------
    file_mps = model_options.path / (file_name + ".mps")
    file_sol = model_options.path / (file_name + ".sol")

    # STEP 2.2:
    # write MILP to file and solve it ...
    if os.path.exists(file_sol):
        # ... unless a solution already exists
        # this is the case if it was generated and then manually solved by
        # the user before
        print(f"Using existing file {file_sol}, make sure it is up to date!")
    else:
        for i_im, impossible_point in enumerate(imposset):
            for ic, constr in enumerate(convex_constraints):
                if constr.is_inequality():
                    outcome = constr.eval(impossible_point) >= 0
                elif constr.is_equation():
                    outcome = constr.eval(impossible_point) == 0
                if outcome is False:
                    R_bar[i_im].append(ic)
        milp_to_minimize_milp = MixedIntegerLinearProgram(
            maximization=False, solver="GLPK"
        )
        Z = milp_to_minimize_milp.new_variable(name="Z", binary=True)
        for r_arr in R_bar:
            if len(r_arr) > 0:
                milp_to_minimize_milp.add_constraint(
                    sum([Z[r] for r in r_arr]) >= 1
                )
        milp_to_minimize_milp.set_objective(sum(Z))
        # suppress_output in order to not make doctests fail
        with suppress_output():
            milp_to_minimize_milp.write_mps(str(file_mps))

        if not isinstance(model_options.milp_solver, NO_MILP_SOLVER_CVL):
            model_options.milp_solver.solve(
                input_file=file_mps,
                solution_file=file_sol,
            )
        else:
            # if there is no milp_solver set in model_options, the user has to solve
            # the MILP manually
            if isinstance(comp, SBox_CVL):
                comp_in_print = "SBox"
            elif isinstance(comp, LinearLayer_CVL):
                comp_in_print = "LinearLayer"
            print(
                f"{comp_in_print} MILP has been written to {file_mps}. "
                "In order to continue the modeling, solve the generated MILP "
                f"by providing a solution file with the name {file_sol}."
            )
            comp._return_immediately_ = True
            return
    final_choices = []  # solution of reduction algorithm
    results, _ = model_options.milp_solver.process_solution_file(file_sol)

    # STEP 3:
    # use the found solution to generate a minimial MILP that models the
    # component
    for Z_index, use in results['Z'].items():
        if use != 0:
            final_choices.append(Z_index)

    for ic, ineq in enumerate(convex_constraints):
        if ic not in final_choices:
            # Only add constraints chosen by final_choices into the MILP
            continue
        tmp_arr = []
        for i, ai in enumerate(ineq.A()):
            # assigns each of the positions in the convex-hull-vector to
            # the corresponding milp variable
            if isinstance(comp, SBox_CVL):
                if i < comp.input_length:
                    # input bits
                    tmp_arr.append(ai * comp.MILP_IN[i])
                elif i < comp.input_length + comp.output_length:
                    # output bits
                    tmp_arr.append(ai * comp.MILP_OUT[i - comp.input_length])
                else:
                    # probability encoding bits
                    tmp_arr.append(
                        ai * PROB[i - comp.input_length - comp.output_length]
                    )

            elif isinstance(comp, LinearLayer_CVL):
                # If we are reducing a LinearLayer_CVL-MILP
                # wordsize is set externally in
                # wordbasedcipher.add_subcipher
                if i < comp.binary_matrix.ncols() // comp.wordsize:
                    tmp_arr.append(ai * comp.MILP_IN[i])
                else:
                    tmp_arr.append(ai * comp.MILP_OUT[
                        i - (comp.input_length // comp.wordsize)
                    ])

        if ineq.is_inequality():
            comp.milp.add_constraint(sum(tmp_arr) + ineq.b() >= 0)
        elif ineq.is_equation():
            comp.milp.add_constraint(sum(tmp_arr) + ineq.b() == 0)
    return


def _to_dict(flat_results):
    r"""
    Convert a flat results dict ``{'Z[0]': 1, 'Z[1]': 2}`` to a nested one
    ``{'Z': {0: 1, 1: 2}}``, grouping by variable name and using the
    bracket index as an integer key.
    """
    nested = {}
    for variable, value in flat_results.items():
        var_name, rest = variable.split("[", 1)
        var_index = int(rest.rstrip("]"))
        nested.setdefault(var_name, {})[var_index] = value
    return nested


def _find_path(cipher, node, path=()):
    """
    Helper function for ``translate_var``. Return the recursion path
    taken to get to ``node``.

        sage: from civerly.util import _find_path
        sage: from civerly.cipher_implementations.ascon import ASCON_CVL
        sage: ascon = ASCON_CVL(3)
        sage: node = ascon.nodes[3].nodes[2].nodes[1]
        sage: _find_path(ascon, node)
        (3, 2, 1)
        
    """
    from civerly.cipher import Cipher
    if id(cipher) == id(node):
        return path
    if not isinstance(cipher, Cipher):
        return None
    for i in range(len(cipher.nodes)):
        sub_path = _find_path(cipher.nodes[i], node, path + (i, ))
        if sub_path is not None:
            return sub_path

def translate_var(cipher, node, local_var):
    """

    TESTS::
        
        sage: from civerly.cipher_implementations.craft import CRAFT_CVL
        sage: from civerly.model_options import *
        sage: import tempfile
        sage: craft = CRAFT_CVL(3)
        sage: # optional - espresso
        sage: with tempfile.TemporaryDirectory() as tmpdir:
        ....:   model_options = MODEL_OPTIONS(
        ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
        ....:     optimization=OPTIMIZATION.SAT,
        ....:     granularity=GRANULARITY.BITWISE,
        ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.MORE_DUMMIES,
        ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
        ....:     sat_solver=CADICAL_CVL(),
        ....:     logic_minimizer=ESPRESSO_CVL(),
        ....:     path=Path(tmpdir))
        ....:   craft.model(model_options)
        7488 variables and 17201 clauses were written to ...
        sage: from civerly.util import translate_var
        sage: node = craft.nodes[1].nodes[2].nodes[1]
        sage: translate_var(craft, node, node.SAT_IN[2])
        643


    """
    index_path = _find_path(cipher, node)
    var = local_var
    # go backwards through the recursion tree
    for depth in range(1, len(index_path)):
        parent = cipher
        for index in index_path[:len(index_path) - depth]:
            parent = parent.nodes[index]
        index = index_path[-depth]
        # distinguish between SAT and MILP variable
        if isinstance(local_var, (int, Integer)):
            var = parent.inv_dictionaries_sat[index][var]
        else:
            var = parent.inv_dictionaries_milp[index][var]

    return var




@contextlib.contextmanager
def suppress_output():
    r"""
    Util function that supresses any output on stdout and stderr.
    Exceptions will not be suppressed, however.

    TESTS::

        sage: from civerly.util import suppress_output
        sage: with suppress_output():
        ....:   print("This is suppressed")
        sage: with suppress_output():
        ....:   assert False
        Traceback (most recent call last):
        ...
        AssertionError
    """
    sys.stdout.flush()
    sys.stderr.flush()
    original_stdout_fd = sys.stdout.fileno()
    original_stderr_fd = sys.stderr.fileno()

    with open(os.devnull, 'w') as devnull:
        new_stdout = os.dup(original_stdout_fd)
        new_stderr = os.dup(original_stderr_fd)
        try:
            os.dup2(devnull.fileno(), original_stdout_fd)
            os.dup2(devnull.fileno(), original_stderr_fd)
            yield
        finally:
            sys.stdout.flush()
            sys.stderr.flush()
            os.dup2(new_stdout, original_stdout_fd)
            os.dup2(new_stderr, original_stderr_fd)
            os.close(new_stdout)
            os.close(new_stderr)
