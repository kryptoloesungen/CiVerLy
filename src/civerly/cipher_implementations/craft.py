from sage.crypto.sbox import SBox as SBox_sage
from sage.matrix.special import block_matrix, identity_matrix, zero_matrix
from sage.rings.finite_rings.finite_field_constructor import GF

from civerly.aeslike import AESlike
from civerly.component import (
    I_CVL,
    LinearLayer_CVL,
    PermuteLayer_CVL,
    RoundkeyXOR_CVL,
    SBox_CVL,
)


class CRAFT_CVL:
    RC = (
        0x11, 0x84, 0x42, 0x25, 0x96, 0xc7, 0x63, 0xb1, 0x54, 0xa2, 0xd5,
        0xe6, 0xf7, 0x73, 0x31, 0x14, 0x82, 0x45, 0x26, 0x97, 0xc3, 0x61,
        0xb4, 0x52, 0xa5, 0xd6, 0xe7, 0xf3, 0x71, 0x34, 0x12, 0x85,
    )  # fmt: skip

    def __init__(self, R, key_schedule=False, name="CRAFT") -> None:
        r"""
        The CiVerLy implementation of CRAFT. It takes the following arguments:

            - ``R`` -- integer; Specifies the number of rounds that are
              performed.

            - ``name`` -- string; The name of the cipher (default: "CRAFT").
              Will be used to name the cipher and the corresponding files
              generated (such as the reports and cipher graphs).

        This cipher is "plug-and-play" usable, i.e. it can be directly used
        when imported.

        EXAMPLES::

            sage: from civerly.util import vec_to_int, int_to_vec
            sage: from civerly.cipher_implementations.craft import CRAFT_CVL
            sage: from civerly.model_options import *
            sage: craft = CRAFT_CVL(10)
            sage: hex(vec_to_int(craft(int_to_vec(0x12345678,64))))
            '0x5d1989d86b887cce'

        Determine the number of active S-boxes using a word-wise model based
        on the the branch number::

            sage: from civerly.cipher_implementations.craft import CRAFT_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: craft = CRAFT_CVL(10)
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - scip
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.MILP,
            ....:     granularity=GRANULARITY.WORDWISE,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.BRANCH_NUMBER,
            ....:     milp_solver=SOLVER.SCIP,
            ....:     path=Path(tmpdir))
            ....:   craft.analyse(model_options)
            5896 variables and 6121 constraints were written to '...'
            10

        Now the improved modeling::

            sage: from civerly.cipher_implementations.craft import CRAFT_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: craft = CRAFT_CVL(10)
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - scip
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.LINEAR,
            ....:     optimization=OPTIMIZATION.MILP,
            ....:     granularity=GRANULARITY.WORDWISE,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.GENERALIZED_WORDWISE,
            ....:     milp_solver=SOLVER.SCIP,
            ....:     path=Path(tmpdir))
            ....:   craft.analyse(model_options)
            5856 variables and 6041 constraints were written to '...'
            36

        Indeed, 36 active S-boxes is a much better bound.

        To get even more explicit results, such as an optimal differential or
        linear trail through CRAFT, we can use bitwise modeling. However,
        this is computationally more difficult than the previous tests::

            sage: from civerly.cipher_implementations.craft import CRAFT_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: craft = CRAFT_CVL(3)
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - scip
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.MILP,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.CONVEX_HULL,
            ....:     sbox_modeling=SBOX_MODELING.CONVEX_HULL,
            ....:     milp_solver=SOLVER.SCIP,
            ....:     path=Path(tmpdir))
            ....:   craft.analyse(model_options)
            7440 variables and 9057 constraints were written to '...'
            8

        Here the objective value is :math:`- \log_2(p)`, with :math:`p` being
        the differential probability (or respectively the linear correlation)
        of the found trail.

        We repeat the same experiment but this time use dummy variables to
        model the linear layer::

            sage: from civerly.cipher_implementations.craft import CRAFT_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: craft = CRAFT_CVL(3)
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - scip
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.MILP,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.MORE_DUMMIES,
            ....:     sbox_modeling=SBOX_MODELING.CONVEX_HULL,
            ....:     milp_solver=SOLVER.SCIP,
            ....:     path=Path(tmpdir))
            ....:   craft.analyse(model_options)
            7728 variables and 8001 constraints were written to '...'
            8

        It is also possible to use SAT to model the cipher. The results should
        match those that MILP-modeling produces::

            sage: from civerly.cipher_implementations.craft import CRAFT_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: craft = CRAFT_CVL(3)
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - cryptominisat  # optional - espresso
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.EXCLUDE_ODD,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     sat_solver=SOLVER.CRYPTOMINISAT,
            ....:     logic_minimizer=SOLVER.ESPRESSO,
            ....:     path=Path(tmpdir))
            ....:   craft.analyse(model_options)
            ....:   craft.generate_report(model_options)
            ....:   trail = str(craft.get_trail(model_options))
            ....:   assert "Unnamed Component" not in trail
            7440 variables and 17201 clauses were written to '...'
            8
            Output file in: ...

        Now with CaDiCaL as solver::

            sage: from civerly.cipher_implementations.craft import CRAFT_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: craft = CRAFT_CVL(3)
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - cadical  # optional - espresso
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.EXCLUDE_ODD,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     sat_solver=SOLVER.CADICAL,
            ....:     logic_minimizer=SOLVER.ESPRESSO,
            ....:     path=Path(tmpdir))
            ....:   craft.analyse(model_options)
            ....:   craft.generate_report(model_options)
            ....:   trail = str(craft.get_trail(model_options))
            ....:   assert "Unnamed Component" not in trail
            7440 variables and 17201 clauses were written to '...'
            8
            Output file in: ...



        TESTS::

            sage: P = 0x0000000000000000
            sage: R1 = 0xCCCCCCCCCAACCCCC
            sage: craft = CRAFT_CVL(R=1)
            sage: c1 = vec_to_int(craft(int_to_vec(P,64)))
            sage: c1 == R1
            True
            sage: P = 0x0000000000000000
            sage: R14 = 0xA9548DEF40B463EE
            sage: craft = CRAFT_CVL(R=14)
            sage: c14 = vec_to_int(craft(int_to_vec(P,64)))
            sage: c14 == R14
            True
        """

        # SBox layer
        # ------------------------------------------------------------------- #
        sboxlayer = AESlike(4, 4, 4, name="SBoxLayer")
        sb = SBox_CVL(SBox_sage((
            0xc, 0xa, 0xd, 0x3, 0xe, 0xb, 0xf, 0x7,
            0x8, 0x9, 0x1, 0x5, 0x0, 0x2, 0x4, 0x6
        )), name="SBox")  # fmt: skip
        for i in range(16):
            node = sboxlayer.add_subcipher(sb, [(sboxlayer.IN, (i, 0))])
            sboxlayer.add_output([(node, (0, i))])
        # ------------------------------------------------------------------- #

        # PermuteNibbles
        tr = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
        transpose = PermuteLayer_CVL(tr, word_coarseness=4, name="Transpose")

        craft_perm = [15, 12, 13, 14, 10, 9, 8, 11, 6, 5, 4, 7, 1, 2, 3, 0]
        craft_perm = [tr[craft_perm[tr[i]]] for i in range(16)]
        pn = PermuteLayer_CVL(craft_perm, word_coarseness=4, name="PermuteNibbles")

        # Generation of the binary matrix of CRAFT-MixColumn
        # ------------------------------------------------------------------- #
        I = identity_matrix(GF(2), 4)  # noqa: E741
        O = zero_matrix(GF(2), 4)  # noqa: E741

        MC_mat = [[I, O, I, I], [O, I, O, I], [O, O, I, O], [O, O, O, I]]

        mc = LinearLayer_CVL(
            block_matrix(GF(2), MC_mat, subdivide=False),
            branch_number_differential=2,
            name="MixColumn",
        )

        # mc_layer = 4x mc in parallel
        mc_layer = AESlike(4, 4, 4, name="MixColumnLayer")
        for j in range(4):
            node = mc_layer.add_subcipher(
                mc, [(mc_layer.IN, (k + 4 * j, k)) for k in range(4)]
            )
            mc_layer.add_output([(node, (k, k + 4 * j)) for k in range(4)])

        # AddRoundConstants, done with RoundkeyXOR_CVL component
        arc_layer = AESlike(4, 4, 4, name="ARC-layer")
        arc = RoundkeyXOR_CVL(8, 0x0, name="AddRoundConstant")

        id1 = I_CVL(4, name="Identity1(4)")
        id2 = I_CVL(12, name="Identity2(12)")
        id3 = I_CVL(40, name="Identity3(40)")

        node_id1 = arc_layer.add_subcipher(id1, [(arc_layer.IN, (0, 0))])
        arc_layer.add_output([(node_id1, (0, 0))])
        node_arc = arc_layer.add_subcipher(
            arc, [(arc_layer.IN, (1, 0)), (arc_layer.IN, (5, 1))]
        )
        arc_layer.add_output([(node_arc, (0, 1)), (node_arc, (1, 5))])
        node_id2 = arc_layer.add_subcipher(
            id2, [(arc_layer.IN, (i, i - 2)) for i in range(2, 5)]
        )
        arc_layer.add_output([(node_id2, (i - 2, i)) for i in range(2, 5)])
        node_id3 = arc_layer.add_subcipher(
            id3, [(arc_layer.IN, (i, i - 6)) for i in range(6, 16)]
        )
        arc_layer.add_output([(node_id3, (i - 6, i)) for i in range(6, 16)])

        # Implementation of CRAFT round
        # ------------------------------------------------------------------- #
        craft_round = AESlike(4, 4, 4, name="CRAFT-round")
        node = craft_round.IN
        node = craft_round.add_subcipher(transpose, [(node, (i, i)) for i in range(16)])
        node = craft_round.add_subcipher(mc_layer, [(node, (i, i)) for i in range(16)])

        node_arclayer = craft_round.add_subcipher(
            arc_layer, [(node, (i, i)) for i in range(16)]
        )
        node = craft_round.add_subcipher(
            pn, [(node_arclayer, (i, i)) for i in range(16)]
        )

        node = craft_round.add_subcipher(sboxlayer, [(node, (i, i)) for i in range(16)])
        node = craft_round.add_subcipher(transpose, [(node, (i, i)) for i in range(16)])
        craft_round.add_output([(node, (i, i)) for i in range(16)])
        # ------------------------------------------------------------------- #

        # Add the round function into the CRAFT cipher
        # ------------------------------------------------------------------- #
        craft_cipher = AESlike(4, 4, 4, name=name)
        node_cipher = craft_cipher.IN

        for r in range(R):
            craft_round.nodes[node_arclayer].nodes[node_arc].const = CRAFT_CVL.RC[r]

            node_cipher = craft_cipher.add_subcipher(
                craft_round, [(node_cipher, (i, i)) for i in range(16)]
            )
        craft_cipher.add_output([(node_cipher, (i, i)) for i in range(16)])
        # ------------------------------------------------------------------- #

        self.craft_cipher = craft_cipher

    def __new__(cls, *args, **kwargs):
        instance = super().__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.craft_cipher
