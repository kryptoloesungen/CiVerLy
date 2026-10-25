import zlib
from dataclasses import dataclass
from itertools import product
from functools import cache
from math import log2
from numbers import Number
from pathlib import Path
from collections.abc import Callable
from typing_extensions import Literal


#
from sage.modules.vector_mod2_dense import Vector_mod2_dense as binvector_t
from sage.modules.free_module_element import vector
from sage.matrix.constructor import Matrix as matrix
from sage.matrix.special import block_matrix, identity_matrix
from sage.rings.finite_rings.finite_field_constructor import GF
from sage.geometry.polyhedron.constructor import Polyhedron
from sage.modules.free_module import VectorSpace
from sage.rings.integer import Integer
from sage.rings.integer_ring import ZZ


#
from ...util import list_of_predecessor_vector_indices, suppress_output
from ... import model_options as MO
from ...component import (
    Component,
    AND_CVL,
    C_CVL,
    I_CVL,
    XOR_CVL,
    ConstXOR_CVL,
    LinearLayer_CVL,
    RotateLayer_CVL,
    ModAdd_CVL,
    PermuteLayer_CVL,
    SBox_CVL,
    ROT_AND_CVL,
)

#
from ..tools import (
    ParityEquation,
    _get_divide_factor,
    int_to_bits,
    bits_to_int,
    _weighted_transition_rel,
    build_eq_t,
    WeightedTransitions,
    Bit,
)

#
from .core import MILPVariable, MILPContext

# [ Utilities for _SAT encoding_ of probablistic transitions ]------ *)
#
#
# [ Precomputation ]------------------------------------------------ *)
#
#
# [ # Two-Bit AND ]------------------------------------------------- *)
#
# precomputation for the 2-to-1 bit ANDs (x AND y)


# [ ABG Helper for ModAdd encoding ]-------------------------------- *)


# [ LinearLayer_CVL ]----------------------------------------------- *)


# [ # bitwise linear layer ]---------------------------------------- *)


def _linear_layer_more_dummies(matrix, IN, OUT, ctx: MILPContext):
    """nil"""
    from math import ceil
    from itertools import chain

    # fmt: off
    equations: tuple[tuple[int], ...] = tuple(
        tuple(i for i, e in enumerate(row) if e > 0) 
        for row in matrix
    )
    for i in set(range(matrix.ncols())).difference(chain.from_iterable(equations)):
        ctx.model.add_constraint(IN[i] == 0)
    # fmt: on

    MILP_DUMMY = ctx.model.new_variable(name="MILP_DUMMY", binary=True)
    doff = 0
    for i, ei in enumerate(equations):
        ell = ceil(log2(len(ei) + 1))
        int_sum = sum(IN[vari] for vari in ei) + OUT[i]
        binary_repr = sum((2 << i) * MILP_DUMMY[doff + i] for i in range(ell))
        doff += ell

        ctx.model.add_constraint(int_sum == binary_repr)

    # Sum_{x in equation} x == 0 (mod 2)
    #
    # dummy = ctx.model.new_variable(integer=True, nonnegative=True, name="MILP_DUMMY")
    # for i, eq in enumerate(equations):
    #     ctx.model.add_constraint(sum(eq.variables) == 2 * dummy[i])


def _linear_layer_convex_hull(component: LinearLayer_CVL, ctx: MILPContext, matrix, IN, OUT):
    # [mtvkn@impulsivebishop]
    # I want to be a smartass again
    # This time, however, I know for a fact that
    # the model will be different because I want to use a different representation
    # of the parity polytope and I don't know if it is a good idea

    from math import ceil
    from itertools import chain

    # fmt: off
    equations: tuple[tuple[int], ...] = tuple(
        tuple(i for i, e in enumerate(row) if e > 0) 
        for row in matrix
    )
    for i in set(range(matrix.ncols())).difference(chain.from_iterable(equations)):
        ctx.model.add_constraint(IN[i] == 0)
    # fmt: on

    # from ..tools import _even_parity_polytope_h_form
    # _even_parity_polytope_h_form(ctx, matrix, IN, OUT)
    # ^^^^^^^^^^^^ gives more constraints, actually

    from ...util import int_to_vec, hw

    for i, tup in enumerate(equations):
        # set of possible transitions: all transitions with even
        # hammingweight (x_1 + x_2 + x_3 = y_1, then 4).
        posset = [
            vector(ZZ, int_to_vec(j, len(tup) + 1))
            for j in range(1 << (len(tup) + 1))
            if hw(j) % 2 == 0
        ]
        convex_hull = Polyhedron(vertices=posset)

        constrs = convex_hull.inequalities() + convex_hull.equations()
        for constr in constrs:
            assert all(component.input_length > u for u in (max(tup), i))

            # sub_constr : substituted constraints (with
            # the appropriate variables)
            sub_constr = (
                constr[0]
                + sum(constr[ind + 1] * IN[tup[ind]] for ind in range(len(constr) - 2))
                + constr[-1] * OUT[i]
            )
            if constr.is_inequality():
                ctx.model.add_constraint(sub_constr >= 0)
            elif constr.is_equation():
                ctx.model.add_constraint(sub_constr == 0)

    return


# [ # wordwise linear layer ]--------------------------------------- *)


def _build_linear_matrix(component: LinearLayer_CVL, o_zero_inds: tuple[int]):
    M = component.binary_matrix.inverse().transpose()
    nrows = component.binary_matrix.nrows()
    return list(M[j] for j in range(nrows) if j in o_zero_inds)


def _build_differential_matrix(component: LinearLayer_CVL, o_zero_inds: tuple[int]):
    M = component.binary_matrix
    nrows = M.nrows()
    return list(M[j] for j in range(nrows) if j in o_zero_inds)


# ----------------------------------------------------------------- *)

matrix_t = list[binvector_t]
get_unsolved_mat_t = Literal[_build_linear_matrix, _build_differential_matrix]


def _linear_layer_generalised_wordwise(
    get_unsolved_mat: get_unsolved_mat_t,
    component: LinearLayer_CVL,
    ctx: MILPContext,
):

    posset = []  # possible set of transitions
    dimensions = []  # kernel-dimensions of each entry

    # wordsize is set externally in wordbasedcipher.add_subcipher
    wordsize = component.wordsize
    binmatrix = component.binary_matrix

    vec_len_in = binmatrix.ncols() // wordsize
    vec_len_out = binmatrix.nrows() // wordsize
    vec_len_both = vec_len_in + vec_len_out

    # all-zero and all-ones vecs for lookup below
    exceptions = ([0] * (vec_len_both), [1] * (vec_len_both))

    def zero_words_bit_pattern(mask: int, nwords: int):
        """compute zero words and their bit indices"""
        nonlocal wordsize

        # The same as:
        #     i_wordarr = int_to_bits(i, vec_len_in)
        #     i_binarr = []
        #     for j in i_wordarr:
        #         i_binarr += all_vecs[j]
        #
        #     i_zero_inds = [
        #         pos for pos in range(len(i_binarr))
        #         if i_binarr[pos] == 0
        #     ]
        #
        # with appropriate name change for variables;
        # We essentially compute the set {j*w + t | a_j = 0 and 0 <= t < w} where w is wordsize
        # and a_j is a bit from the binary array expanded from word array

        words = int_to_bits(mask, nwords)
        zero_inds = [
            word_i * wordsize + bit
            for word_i, active in enumerate(words)
            if active == 0
            for bit in range(wordsize)
        ]
        return words, tuple(zero_inds)

    # Go over all input patterns
    for i in range(1 << vec_len_in):
        i_wordarr, i_zero_inds = zero_words_bit_pattern(i, vec_len_in)

        # Go over all output patterns
        for o in range(1 << vec_len_out):
            o_wordarr, o_zero_inds = zero_words_bit_pattern(o, vec_len_out)

            # matrix_to_be_solved is a submatrix of the linear layer,
            # together with additional rows restricting the
            # corresponding inputs to be zero
            matrix_to_be_solved = get_unsolved_mat(component, o_zero_inds)

            # Append the additional rows forcing the corresponding
            # input to be zero
            for zero_index in i_zero_inds:
                new_row = [0 for _ in range(binmatrix.ncols())]
                new_row[zero_index] = 1
                matrix_to_be_solved.append(new_row)

            wordarr = i_wordarr + o_wordarr
            # Two special cases: [0,...,0], [1,...,1] are recognized
            # as impossible (since the matrix is trivial then)

            current_dimension = binmatrix.ncols() - matrix(GF(2), matrix_to_be_solved).rank()
            # current_dimension = matrix(GF(2), matrix_to_be_solved).right_kernel().dimension()
            dimensions.append(current_dimension)

            # wordsize is set externally in
            # wordbasedcipher.add_subcipher
            predecessors = list_of_predecessor_vector_indices(vector(GF(2), wordarr), vec_len_both)
            # predecessors contains
            # {u | u \prec (i_wordarr + o_wordarr)},
            # with u \prec v <=> u_i \leq v_i \forall i

            # Only a possible transition if the
            # solution-space is **larger** than before
            is_exc = wordarr in exceptions
            curdim_gt_prevdims = all(
                current_dimension > dimensions[index_dim] for index_dim in predecessors
            )

            if (current_dimension > 0 and curdim_gt_prevdims) or is_exc:
                posset.append(wordarr)

    # ----------------------------------------------------------------- *)
    reduction_algorithm_ST17(component, ctx, posset)


# ----------------------------------------------------------------- *)

bn_t = Literal["differential", "linear"]


def _linear_layer_branch_number(bn: bn_t, component: LinearLayer_CVL, ctx: MILPContext):

    # this should be verified at `__init__` time
    bn = getattr(component, f"branch_number_{bn}", None)
    if bn is None:
        raise ValueError(
            "No branch number specified, specify it when "
            "initializing the LinearLayer_CVL component."
        )

    ACTIVE = ctx.model.new_variable(binary=True, name="ACTIVE")
    IN = ctx.IN
    OUT = ctx.OUT

    # wordsize is set externally in wordbasedcipher.add_subcipher
    wordsize = component.wordsize
    words_in = component.input_length // wordsize
    words_out = component.output_length // wordsize

    # fmt: off
    ctx.model.add_constraint(
          sum([IN[j] for j in range(words_in)])  
        + sum([OUT[j] for j in range(words_out)])
        >= bn * ACTIVE[0]
    )
    # fmt: on

    # If one of the columns words is active, MixColumns will be active
    for j in range(words_in):
        ctx.model.add_constraint(ACTIVE[0] >= IN[j])
    for j in range(words_out):
        ctx.model.add_constraint(ACTIVE[0] >= OUT[j])

    ctx.model.add_constraint(ACTIVE[0] <= sum(IN[j] for j in range(words_in)))
    ctx.model.add_constraint(ACTIVE[0] <= sum(OUT[j] for j in range(words_out)))


# ----------------------------------------------------------------- *)
# slight change to the `reduction_algorithm_ST17` from civerly.util to accommodate the introduced
# arch. changes
def reduction_algorithm_ST17(
    component: LinearLayer_CVL | SBox_CVL, ctx: MILPContext, posset, PROB=None
):
    r"""
    Implements Yosuke Todos and Yu Sasakis Reduction Algorithm
    (https://link.springer.com/chapter/10.1007/978-3-319-69284-5_11),
    which models the problem of choosing a minimal subset of
    MILP-constraints as a MILP itself. Intended to be used internally.
    """
    # assert isinstance(component, (SBox_CVL, LinearLayer_CVL))

    from ...component import LinearLayer_CVL, SBox_CVL
    from ...problem import MILP_CVL

    model_options = ctx.options

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
    if isinstance(component, LinearLayer_CVL):
        compmat = component.binary_matrix
        file_name = (
            component.name
            + str(sum([ZZ(i) for i in compmat[0]]))
            + str(sum([ZZ(j) for i in compmat for j in i]))
            + str(sum([ZZ(i) for i in compmat[-1]]))
        )
    elif isinstance(component, SBox_CVL):
        file_name = (
            f"{zlib.crc32(''.join([f'{s_entry:x}' for s_entry in component.S]).encode('utf-8')):x}"
        )
    else:
        # [mtvkn@impulsivebishop] ok, but then we do not need the assertion check above
        raise ValueError(
            "reduction_algorithm_ST17 can only be applied to "
            f"LinearLayer_CVL or SBox_CVL, not to {type(component)}"
        )
    # ------------------------------------------------------------------------
    file_mps = model_options.path / (file_name + ".mps")

    # STEP 2.2:
    # Write the reduction MILP and solve it. The solver itself handles the
    # "solution already on disk" cache check and (for an external solver)
    # aborts via :class:`ExternalSolveRequiredError` when the user must solve.
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
            milp_to_minimize_milp.add_constraint(sum([Z[r] for r in r_arr]) >= 1)
    milp_to_minimize_milp.set_objective(sum(Z))
    # suppress_output in order to not make doctests fail
    with suppress_output():
        milp_to_minimize_milp.write_mps(str(file_mps))

    result = model_options.milp_solver.solve(file_mps)
    results = result["assignment"]
    final_choices = []  # solution of reduction algorithm

    # STEP 3:
    # use the found solution to generate a minimal MILP that models the
    # component
    for Z_index, use in results["Z"].items():
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
            if isinstance(component, SBox_CVL):
                in_len, out_len = component.input_length, component.output_length
                IN, OUT = ctx.IN, ctx.OUT

                if i < in_len:
                    # input bits
                    tmp_arr.append(ai * IN[i])
                elif i < in_len + out_len:
                    # output bits
                    tmp_arr.append(ai * OUT[i - in_len])
                else:
                    # probability encoding bits
                    tmp_arr.append(ai * PROB[i - in_len - out_len])

            elif isinstance(component, LinearLayer_CVL):
                compmat = component.binary_matrix
                in_len, out_len = component.input_length, component.output_length
                wordsize = component.wordsize
                IN, OUT = ctx.IN, ctx.OUT

                # If we are reducing a LinearLayer_CVL-MILP
                # wordsize is set externally in
                # wordbasedcipher.add_subcipher
                if i < compmat.ncols() // wordsize:
                    tmp_arr.append(ai * IN[i])
                else:
                    tmp_arr.append(ai * OUT[i - (in_len // wordsize)])

        if ineq.is_inequality():
            ctx.model.add_constraint(sum(tmp_arr) + ineq.b() >= 0)
        elif ineq.is_equation():
            ctx.model.add_constraint(sum(tmp_arr) + ineq.b() == 0)
    return
