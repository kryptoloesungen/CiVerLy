from sage.crypto.sbox import SBox as SBox_sage
from sage.matrix.special import block_matrix, identity_matrix, zero_matrix
from sage.rings.finite_rings.finite_field_constructor import GF

from civerly.aeslike import AESlike
from civerly.cipher_implementations.base import CipherImplementation_CVL
from civerly.component import (
    LinearLayer_CVL,
    RoundkeyXOR_CVL,
    SBox_CVL,
)


class CRAFT_CVL(CipherImplementation_CVL, AESlike):
    RC = (
        0x11, 0x84, 0x42, 0x25, 0x96, 0xc7, 0x63, 0xb1, 0x54, 0xa2, 0xd5,
        0xe6, 0xf7, 0x73, 0x31, 0x14, 0x82, 0x45, 0x26, 0x97, 0xc3, 0x61,
        0xb4, 0x52, 0xa5, 0xd6, 0xe7, 0xf3, 0x71, 0x34, 0x12, 0x85,
    )  # fmt: skip

    def __init__(self, R=32, key_schedule=None, key=None, name="CRAFT") -> None:
        r"""
        The CiVerLy implementation of CRAFT. It takes the following arguments:

            - ``R`` -- integer (default: ``32``); Specifies the number of
              rounds that are performed. Full CRAFT has 32 rounds
              (Beierle et al., ToSC 2019).

            - ``key_schedule`` -- :class:`civerly.keyschedule.KeySchedule`
              (optional); Key schedule instance used by ``set_round_keys`` to
              derive round keys from a master key. No built-in key schedule is
              implemented for CRAFT; pass a custom ``KeySchedule`` subclass
              instance. Defaults to ``None`` (no key schedule).

            - ``key`` -- integer (optional); The master key passed to
              ``key_schedule``, injected via ``set_round_keys`` when both are
              given. Note that CRAFT currently has no round key components,
              so ``set_round_keys`` is not supported.

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
            2736 variables and 2961 constraints were written to '...'
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
            2696 variables and 2881 constraints were written to '...'
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
            3648 variables and 5265 constraints were written to '...'
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
            3936 variables and 4209 constraints were written to '...'
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
            3648 variables and 9617 clauses were written to '...'
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
            3648 variables and 9617 clauses were written to '...'
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
        super().__init__(4, 4, 4, R=R, key_schedule=key_schedule, key=key, name=name)

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

        # Implementation of CRAFT round
        # ------------------------------------------------------------------- #
        # The state is row-major (cell 4i + j is row i, column j), as in the
        # specification. ``state[c]`` is the (node, word) currently holding
        # cell ``c``; MixColumn, the round constants and PermuteNibbles are
        # done by wiring.
        craft_round = AESlike(4, 4, 4, name="CRAFT-round")
        state = {c: (craft_round.IN, c) for c in range(16)}

        # MixColumn on every column j = cells (j, 4 + j, 8 + j, 12 + j)
        for j in range(4):
            node = craft_round.add_subcipher(
                mc, [(state[4 * i + j][0], (state[4 * i + j][1], i)) for i in range(4)]
            )
            for i in range(4):
                state[4 * i + j] = (node, i)

        # AddRoundConstants on cells 4 and 5; the constant is set per round
        arc = RoundkeyXOR_CVL(8, 0x0, name="AddRoundConstant")
        node_arc = craft_round.add_subcipher(
            arc, [(state[c][0], (state[c][1], k)) for k, c in enumerate((4, 5))]
        )
        state[4], state[5] = (node_arc, 0), (node_arc, 1)

        # PermuteNibbles: cell i moves to cell craft_perm[i]
        craft_perm = [15, 12, 13, 14, 10, 9, 8, 11, 6, 5, 4, 7, 1, 2, 3, 0]
        state = {craft_perm[c]: state[c] for c in range(16)}

        node = craft_round.add_subcipher(
            sboxlayer, [(state[c][0], (state[c][1], c)) for c in range(16)]
        )
        craft_round.add_output([(node, (i, i)) for i in range(16)])
        # ------------------------------------------------------------------- #

        # Add the round function into the CRAFT cipher
        # ------------------------------------------------------------------- #
        node_cipher = self.IN

        for r in range(self.R):
            craft_round.nodes[node_arc].const = CRAFT_CVL.RC[r]

            node_cipher = self.add_subcipher(
                craft_round, [(node_cipher, (i, i)) for i in range(16)]
            )
        self.add_output([(node_cipher, (i, i)) for i in range(16)])
        # ------------------------------------------------------------------- #
