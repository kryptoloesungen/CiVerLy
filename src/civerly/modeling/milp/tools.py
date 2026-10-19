import zlib
from dataclasses import dataclass
from itertools import product
from functools import cache
from math import log2
from numbers import Number
from pathlib import Path
from collections.abc import Callable


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
from ..tools import _weighted_transition_rel
from ..tools import _get_divide_factor, int_to_bits, bits_to_int
from ..tools import WeightedTransitions, Bit
from ..tools import ParityEquation

#
from .core import MILPVar, MILPContext

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


# [ # wordwise linear layer ]--------------------------------------- *)

matrix_t = list[binvector_t]


def _linear_layer_generalised_wordwise(
    component: LinearLayer_CVL, ctx: MILPContext, get_equations: Callable[[list[int]], matrix_t]
):

    compmat = component.binary_matrix

    # wordsize is set externally in wordbasedcipher.add_subcipher
    wordsize = component.wordsize
    ncols = compmat.ncols()
    nrows = compmat.nrows()

    #
    n_input_words = ncols // wordsize
    n_output_words = nrows // wordsize
    vec_len_both = n_input_words + n_output_words
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
        return words, zero_inds

    #
    posset = []  # possible set of transitions
    dimensions = []  # kernel-dimensions of each entry

    for i in range(1 << n_input_words):
        i_wordarr, i_zero_inds = zero_words_bit_pattern(i, n_input_words)

        # Go over all output patterns
        for o in range(1 << n_output_words):
            o_wordarr, o_zero_inds = zero_words_bit_pattern(o, n_output_words)

            matrix_to_be_solved = list(get_equations(o_zero_inds))

            # Append the additional rows forcing the corresponding
            # input to be zero
            for zero_index in i_zero_inds:
                new_row = [0] * ncols
                new_row[zero_index] = 1
                matrix_to_be_solved.append(new_row)

            #
            zero_words = i_wordarr + o_wordarr

            current_dimension = matrix(GF(2), matrix_to_be_solved).right_kernel().dimension()
            # current_dimension = ncols - matrix(GF(2), matrix_to_be_solved).rank()
            dimensions.append(current_dimension)

            # wordsize is set externally in
            # wordbasedcipher.add_subcipher
            predecessors = list_of_predecessor_vector_indices(
                vector(GF(2), zero_words), vec_len_both
            )
            # predecessors contains
            # {u | u \prec (i_wordarr + o_wordarr)},
            # with u \prec v <=> u_i \leq v_i \forall i

            # Two special cases: [0,...,0], [1,...,1] are recognized
            # as impossible (since the matrix is trivial then)
            is_exc = zero_words in exceptions
            greater_dim_then_pred = all(
                current_dimension > dimensions[index_dim] for index_dim in predecessors
            )

            # Only a possible transition if the
            # solution-space is **larger** than before
            if is_exc or (current_dimension > 0 and greater_dim_then_pred):
                posset.append(zero_words)

    reduction_algorithm_ST17(component, ctx, posset)


# ----------------------------------------------------------------- *)


def _linear_layer_branch_number(component: LinearLayer_CVL, ctx: MILPContext, bn: int = None):

    # this should be verified at `__init__` time
    if bn is None:
        raise ValueError(
            "No branch number specified, specify it when "
            "initializing the LinearLayer_CVL component."
        )

    ACTIVE = ctx.model.new_variable(binary=True, name="ACTIVE")
    IN = ctx.IN
    OUT = ctx.OUT

    # wordsize is set externally in wordbasedcipher.add_subcipher
    words_in = component.input_length // component.wordsize
    words_out = component.output_length // component.wordsize

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

    from civerly.component import LinearLayer_CVL, SBox_CVL
    from civerly.milp import MILP_CVL

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
