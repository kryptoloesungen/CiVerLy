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
import shutil
import zlib
import sys
import os

from sage.rings.integer_ring import ZZ
from sage.rings.integer import Integer
from sage.rings.finite_rings.finite_field_constructor import GF
from sage.modules.free_module_element import vector
from sage.modules.free_module import VectorSpace
from sage.geometry.polyhedron.constructor import Polyhedron


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
        sage: from civerly.milp import MILP_CVL
        sage: milp = MILP_CVL(maximization=False)
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
        sage: from civerly.milp import MILP_CVL
        sage: milp = MILP_CVL(maximization=False)
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


def reduction_algorithm_ST17(comp, posset, model_options, PROB=None):
    r"""
    Implements Yosuke Todos and Yu Sasakis Reduction Algorithm
    (https://link.springer.com/chapter/10.1007/978-3-319-69284-5_11),
    which models the problem of choosing a minimal subset of
    MILP-constraints as a MILP itself. Intended to be used internally.
    """
    from civerly.component import SBox_CVL, LinearLayer_CVL
    from civerly.milp import MILP_CVL

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

    # STEP 2.2:
    # Write the reduction MILP and solve it. The solver itself handles the
    # "solution already on disk" cache check and (for an external solver)
    # aborts via :class:`ExternalSolveRequired` when the user must solve.
    for i_im, impossible_point in enumerate(imposset):
        for ic, constr in enumerate(convex_constraints):
            if constr.is_inequality():
                outcome = constr.eval(impossible_point) >= 0
            elif constr.is_equation():
                outcome = constr.eval(impossible_point) == 0
            if outcome is False:
                R_bar[i_im].append(ic)
    milp_to_minimize_milp = MILP_CVL(maximization=False)
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

    result = model_options.milp_solver.solve(file_mps)
    results = result["assignment"]
    final_choices = []  # solution of reduction algorithm

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
                    tmp_arr.append(ai * comp.milp.VAR_IN[i])
                elif i < comp.input_length + comp.output_length:
                    # output bits
                    tmp_arr.append(ai * comp.milp.VAR_OUT[i - comp.input_length])
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
                    tmp_arr.append(ai * comp.milp.VAR_IN[i])
                else:
                    tmp_arr.append(ai * comp.milp.VAR_OUT[
                        i - (comp.input_length // comp.wordsize)
                    ])

        if ineq.is_inequality():
            comp.milp.add_constraint(sum(tmp_arr) + ineq.b() >= 0)
        elif ineq.is_equation():
            comp.milp.add_constraint(sum(tmp_arr) + ineq.b() == 0)
    return


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
        ....:     sat_solver=SOLVER.CADICAL,
        ....:     logic_minimizer=SOLVER.ESPRESSO,
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

def _read_mps(path):
    r"""
    Parse an MPS file written by
    :meth:`MixedIntegerLinearProgram.write_mps` and return a
    :class:`sage.numerical.mip.MixedIntegerLinearProgram` containing
    the variables, constraints, and objective from the file.

    This is needed because
    :class:`sage.numerical.backends.glpk_backend.GLPKBackend` does not
    have a ``read_mps`` method implemented.

    An MPS file contains the following information:
    
    - ROWS: The constraints of the MILP. Each row equals one constraint.
        - 'N': The objective row
        - 'E': A row with equality '=='
        - 'L': A row with '<='
        - 'G': A row with '>='

    - COLUMNS: Contains variable name, each row in which it appears + the coefficients
        - example: 'X14[21]  R0001484    1   R0001474    -1'
        
    - RHS: Specifies the rhs value of each row. If row is not included, the rhs-value is 0.
        - example: 'RHS1    R0002580    4   R0002581    3'

    INPUT:

        - ``path`` -- string or path-like; path to the ``.mps`` file.

    OUTPUT:

        A :class:`sage.numerical.mip.MixedIntegerLinearProgram` instance
        (minimization, GLPK solver) ready to be solved.

    TESTS:

        sage: # optional - espresso
        sage: from civerly.cipher_implementations.toy_ciphers.toy3 \
        ....:   import Toy3
        sage: from civerly.model_options import *
        sage: cipher = Toy3()
        sage: import tempfile
        sage: with tempfile.TemporaryDirectory(delete=False) as tmpdir:
        ....:   model_options = MODEL_OPTIONS(
        ....:       cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
        ....:       optimization=OPTIMIZATION.MILP,
        ....:       granularity=GRANULARITY.BITWISE,
        ....:       linear_layer_modeling=LINEAR_LAYER_MODELING.MORE_DUMMIES,
        ....:       sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
        ....:       logic_minimizer=ESPRESSO_CVL(),
        ....:       path=Path(tmpdir))
        sage: cipher.model(model_options)
        854 variables and 2993 constraints were written to ...
        Boolean Program (minimization, 854 variables, 2993 constraints)
        sage: from civerly.util import _read_mps
        sage: _read_mps(model_options.path / f"{cipher.name}.mps")
        Boolean Program (minimization, 854 variables, 2993 constraints)
        sage: import shutil
        sage: shutil.rmtree(tmpdir)


    """
    
    # stores current section inside MPS file.
    # is one of 'ROWS', 'COLUMNS', 'RHS', 'BOUNDS'.
    section = None
    
    # name of the objective row
    obj_row = None
    
    # contains the constraint rows: [(R0001253, E), ...]
    row_order = []

    # variable names in order of first appearance
    variables = []
    
    # dictionary mapping variable to row of occurence (+ coefficient)
    # example: 'X3[12]' -> {R0002653: 1.0}
    var_coeffs = {}

    # Contains the constant part (rhs) of each row
    # {R0001351: -10.0, ...}
    rhs = {}
    
    # var_name -> {'lower': float|None, 'upper': float|None}
    bounds_data = {}
    
    # variables declared inside an INTORG...INTEND block,
    # i.e. integer variables inside this MILP.
    # -> ['X1[2]', ..., 'X4[21]']
    integer_vars = []

    in_integer_block = False

    # parse the MPS file
    with open(path) as f:
        for line in f.readlines():
            if line[0] in ('*', '$'):
                continue  # blank line or comment

            # Section headers start at column 0 (no leading whitespace or empty lines)
            if line[0] not in (' ', '\t', '\n'):
                section = line.split()[0].upper()
                continue

            tokens = line.split()
            # ------------------------------------------------
            # collect all rows in row_order
            if section == 'ROWS':
                assert len(tokens) == 2, (
                    "MPS file is formatted wrongly in section ROWS"
                )
                rtype, rname = tokens
                # there is only one 'N'-row (containing the objective)
                if rtype == 'N':
                    obj_row = rname
                else:
                    row_order.append((rname, rtype))
            # ------------------------------------------------
            elif section == 'COLUMNS':
                # if current line is the header of the COLUMNS table
                if len(tokens) >= 3 and tokens[1] == "'MARKER'":
                    in_integer_block = (tokens[2] == "'INTORG'")
                    continue

                vname = tokens[0]
                if vname not in variables:
                    variables.append(vname)
                    var_coeffs[vname] = {}
                    if in_integer_block:
                        integer_vars.append(vname)
                
                # parse occurences into var_coeffs
                i = 1
                while i + 1 < len(tokens):
                    var_coeffs[vname][tokens[i]] = float(tokens[i + 1])
                    i += 2
            # ------------------------------------------------
            elif section == 'RHS':
                i = 1
                while i + 1 < len(tokens):
                    rhs[tokens[i]] = float(tokens[i + 1])
                    i += 2
            # ------------------------------------------------
            elif section == 'BOUNDS':
                assert len(tokens) == 4, (
                    "MPS file is formatted wrongly in section BOUNDS"
                )
                btype = tokens[0].upper()
                vname = tokens[2]
                val = float(tokens[3]) if len(tokens) > 3 else None
                if vname not in bounds_data:
                    bounds_data[vname] = {'lower': 0.0, 'upper': None}
                b = bounds_data[vname]
                if btype == 'UP':   # upper
                    b['upper'] = val
                elif btype == 'LO': # lower
                    b['lower'] = val
                elif btype == 'FX': # fix
                    b['lower'] = val
                    b['upper'] = val
                elif btype == 'FR': # free
                    b['lower'] = None
                    b['upper'] = None
                elif btype == 'MI':
                    b['lower'] = None
                elif btype == 'BV': # binary variable
                    b['lower'], b['upper'] = 0.0, 1.0
            # ------------------------------------------------


    # --- Build the MILP from the parsed data ---
    milp = MixedIntegerLinearProgram(maximization=False, solver="GLPK")
    backend = milp.get_backend()
    var_to_col = {}
    obj_coeffs = []
    for col_idx, vname in enumerate(variables):
        b = bounds_data.get(vname, {'lower': 0.0, 'upper': None})
        lower, upper = b['lower'], b['upper']

        # indicates whether current variable is an integer or binary
        is_int = vname in integer_vars
        is_bin = is_int and lower == 0.0 and upper == 1.0
        
        # construct objective
        # (by checking whether vname is part of the objective-row)
        obj_coeff = var_coeffs[vname].get(obj_row, 0.0)
        obj_coeffs.append(obj_coeff)

        var_to_col[vname] = col_idx
        backend.add_variable(
            lower_bound=lower,
            upper_bound=upper,
            binary=is_bin,
            integer=is_int and not is_bin,
            obj=obj_coeff,
            name=vname,
        )

    # set objective
    if obj_coeffs:
        backend.set_objective(obj_coeffs)

    # add constraints back in
    for rname, rtype in row_order:
        # construct coefficients vector
        coeffs = [
            (var_to_col[vname], var_coeffs[vname][rname])
            for vname in variables
            if rname in var_coeffs[vname]
        ]
        rhs_val = rhs.get(rname, 0.0)
        if rtype == 'L': # '<='
            lb, ub = None, rhs_val
        elif rtype == 'G': # '<='
            lb, ub = rhs_val, None
        else:  # 'E', '=='
            lb, ub = rhs_val, rhs_val

        # add into backend
        backend.add_linear_constraint(coeffs, lb, ub, name=rname)

    return milp



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
