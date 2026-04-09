from civerly.aeslike import AESlike
from civerly.wordsboxcipher import WordSBoxCipher  # For the TK-schedules
from civerly.component import SBox_CVL, PermuteLayer_CVL, RoundkeyXOR_CVL
from civerly.component import LinearLayer_CVL, I_CVL
from civerly.util import int_to_vec, vec_to_int
from sage.crypto.sbox import SBox
from sage.rings.finite_rings.finite_field_constructor import GF
from sage.matrix.special import zero_matrix, identity_matrix, block_matrix
from sage.matrix.constructor import Matrix as matrix


class SKINNY_CVL:
    consts = [
        0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3E, 0x3D, 0x3B, 0x37, 0x2F, 0x1E,
        0x3C, 0x39, 0x33, 0x27, 0x0E, 0x1D, 0x3A, 0x35, 0x2B, 0x16, 0x2C,
        0x18, 0x30, 0x21, 0x02, 0x05, 0x0B, 0x17, 0x2E, 0x1C, 0x38, 0x31,
        0x23, 0x06, 0x0D, 0x1B, 0x36, 0x2D, 0x1A, 0x34, 0x29, 0x12, 0x24,
        0x08, 0x11, 0x22, 0x04, 0x09, 0x13, 0x26, 0x0C, 0x19, 0x32, 0x25,
        0x0A, 0x15, 0x2A, 0x14, 0x28, 0x10, 0x20
    ]

    def create_tk_schedules(s, z):
        r"""
        Helper function, creating the Tweakey schedules.
        These arent AESlike ciphers because of the LFSR layer not obeying the
        "MixColumn-condition" for AESlike ciphers.

        The reference values below are taken from the SKINNY implementation
        in (https://github.com/hadipourh/skinny). Note that these also align
        with the test vectors from the SKINNY paper
        (https://eprint.iacr.org/2016/660.pdf).

        TESTS::

            sage: from civerly.cipher_implementations.skinny import SKINNY_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: tk_schedules = SKINNY_CVL.create_tk_schedules(s=4, z=3)
            sage: tk1_reference_values = [
            ....:   0x9eb93640d088da63, 0x03da86d89eb93640, 0xe096b43903da86d8,
            ....:   0x3806dd8ae096b439, 0x09e493b63806dd8a, 0x8a3d08d609e493b6,
            ....:   0x9603eb948a3d08d6, 0xa6883d0d9603eb94, 0x649b09e3a6883d0d,
            ....:   0x6dad8038649b09e3, 0x43699e0b6dad8038, 0xd860a38d43699e0b,
            ....:   0x3b4e6099d860a38d, 0x8dd368a03b4e6099, 0xb930496e8dd368a0,
            ....:   0xd088da63b930496e
            ....: ]
            sage: tk1_actual_value = 0x9eb93640d088da63
            sage: tk1_correct = True
            sage: for i in range(32):
            ....:   tk1_actual_value = vec_to_int(tk_schedules[0](
            ....:       int_to_vec(tk1_actual_value, 64)))
            ....:   # TK1 values are cyclic with order 16
            ....:   tk1_correct &= (tk1_actual_value == \
            ....:       tk1_reference_values[(i+1) % 16])
            sage: tk1_correct
            True
            sage: tk2_reference_values = [
            ....: 0x76a39d1c8bea71e1, 0x7212ccf576a39d1c, 0xd8fa52367212ccf5,
            ....: 0x4bf82e84d8fa5236, 0x1da4e6b54bf82e84, 0x799ce1411da4e6b5,
            ....: 0xab2d57c9799ce141, 0x32f239c8ab2d57c9, 0x735f48ba32f239c8,
            ....: 0x4163e864735f48ba, 0x65f1b79e4163e864, 0x2991ddc665f1b79e,
            ....: 0xbcdfe3722991ddc6, 0x3d4a38a2bcdfe372, 0x8476afce3d4a38a2,
            ....: 0xa46195658476afce, 0x9c1ef85da4619565, 0x9b5bdd329c1ef85d,
            ....: 0x8a312bec9b5bdd32, 0x743ab6a78a312bec, 0x58176c42743ab6a7,
            ....: 0x9ffd657558176c42, 0x14b829df9ffd6575, 0xeb3befda14b829df,
            ....: 0x9e237a41eb3befda, 0x75ce6ac79e237a41, 0xc23549f675ce6ac7,
            ....: 0xbff588dcc23549f6, 0x4d836e9bbff588dc, 0xe871ea1b4d836e9b,
            ....: 0xa79c13d6e871ea1b, 0x17c5f2c2a79c13d6, 0xfd563a2817c5f2c2,
            ....: 0xf42488ebfd563a28, 0xa1e5b46df42488eb, 0x97e14c19a1e5b46d
            ....: ]
            sage: tk2_actual_value = 0x76a39d1c8bea71e1
            sage: tk2_correct = True
            sage: for i in range(35):
            ....:   tk2_actual_value = vec_to_int(tk_schedules[1](int_to_vec(
            ....:       tk2_actual_value, 64)))
            ....:   tk2_correct &= (tk2_actual_value == \
            ....:       tk2_reference_values[i+1])
            sage: tk2_correct
            True
            sage: tk3_reference_values = [
            ....:   0xb2dbb41b422dfcd0, 0x102e1676b2dbb41b, 0x15526855102e1676,
            ....:   0x03831b8f15526855, 0xaa8caa3103831b8f, 0x9705cc89aa8caa31,
            ....:   0xd8ddc9de9705cc89, 0xb44e0cead8ddc9de, 0xcf6466e6b44e0cea,
            ....:   0x2d5e2f0fcf6466e6, 0x73e33f322d5e2f0f, 0x6717a01f73e33f32,
            ....:   0x91b7f9996717a01f, 0xb73088db91b7f999, 0x8444547bb73088db,
            ....:   0xb55c96c08444547b, 0x25c22ba2b55c96c0, 0xa053ae4e25c22ba2,
            ....:   0xa115ed11a053ae4e, 0x0fdfa2d9a115ed11, 0x88d688fa0fdfa2d9,
            ....:   0x740166d788d688fa, 0xcdcc67c3740166d7, 0x2bb30638cdcc67c3,
            ....:   0x69ebee3e2bb30638, 0x5c13590969ebee3e, 0x4f3ff9f55c135909,
            ....:   0xe4a480a94f3ff9f5, 0x7a249777e4a480a9, 0x24f0ddc27a249777,
            ....:   0xdbbb1b4224f0ddc2, 0x21167e60dbbb1b42, 0x5165528521167e60,
            ....:   0x801f83b351655285, 0x8aa13caa801f83b3, 0x09c985c78aa13caa,
            ....:   0xddcedd9809c985c7, 0x4b0aeec4ddcedd98, 0x6c66e46f4b0aeec4,
            ....:   0x522f0efd6c66e46f
            ....: ]
            sage: tk3_actual_value = 0xb2dbb41b422dfcd0
            sage: tk3_correct = True
            sage: for i in range(39):
            ....:   tk3_actual_value = vec_to_int(tk_schedules[2](int_to_vec(
            ....:       tk3_actual_value, 64)))
            ....:   tk3_correct &= (tk3_actual_value == \
            ....:       tk3_reference_values[i+1])
            sage: tk3_correct
            True

        """
        pt_perm = [9, 15, 8, 13, 10, 14, 12, 11, 0, 1, 2, 3, 4, 5, 6, 7]
        PT = PermuteLayer_CVL([pt_perm[i] for i in range(16)], word_coarseness=s, name="PT").inv()

        # TK1-schedule
        # ------------------------------------------------------------
        tk1_schedule = WordSBoxCipher(s, 16, 16, name="TK1")
        node_tk1 = tk1_schedule.add_subcipher(
            PT, [(tk1_schedule.IN, (i, i)) for i in range(16)]
        )
        tk1_schedule.add_output([(node_tk1, (i, i)) for i in range(16)])

        # TK2-schedule
        # ------------------------------------------------------------
        if z > 1:
            tk2_schedule = WordSBoxCipher(s, 16, 16, name="TK2")
            node_tk2_pt = tk2_schedule.add_subcipher(
                PT, [(tk2_schedule.IN, (i, i)) for i in range(16)]
            )

            if s == 4:
                lfsr2_mat = [[0, 1, 0, 0],
                             [0, 0, 1, 0],
                             [0, 0, 0, 1],
                             [1, 1, 0, 0]]
            else:  # if s == 8
                lfsr2_mat = [[0, 1, 0, 0, 0, 0, 0, 0],
                             [0, 0, 1, 0, 0, 0, 0, 0],
                             [0, 0, 0, 1, 0, 0, 0, 0],
                             [0, 0, 0, 0, 1, 0, 0, 0],
                             [0, 0, 0, 0, 0, 1, 0, 0],
                             [0, 0, 0, 0, 0, 0, 1, 0],
                             [0, 0, 0, 0, 0, 0, 0, 1],
                             [1, 0, 1, 0, 0, 0, 0, 0]]
            LFSR2 = LinearLayer_CVL(matrix(GF(2), lfsr2_mat), name="LFSR2")

            lfsr_layer = WordSBoxCipher(s, 16, 16, name="lfsr_layer2")
            for j in range(2):  # Add LFSRs
                for i in range(4):
                    node_lfsr2 = lfsr_layer.add_subcipher(
                        LFSR2, [(lfsr_layer.IN, (i + 4*j, 0))]
                    )
                    lfsr_layer.add_output([(node_lfsr2, (0, i + 4*j))])
            for j in range(2, 4):  # Connect the rest directly to output
                lfsr_layer.add_output(
                    [(lfsr_layer.IN, (4*j + i, 4*j + i)) for i in range(4)]
                )

            node_tk2 = tk2_schedule.add_subcipher(
                lfsr_layer, [(node_tk2_pt, (i, i)) for i in range(16)]
            )  # add LFSR layer
            tk2_schedule.add_output([(node_tk2, (i, i)) for i in range(16)])

        # TK3-schedule
        # ------------------------------------------------------------
        if z == 3:
            tk3_schedule = WordSBoxCipher(s, 16, 16, name="TK3")
            node_tk3_pt = tk3_schedule.add_subcipher(
                PT, [(tk3_schedule.IN, (i, i)) for i in range(16)]
            )

            if s == 4:
                lfsr3_mat = [[1, 0, 0, 1],
                             [1, 0, 0, 0],
                             [0, 1, 0, 0],
                             [0, 0, 1, 0]]
            else:  # if s == 8
                lfsr3_mat = [[0, 1, 0, 0, 0, 0, 0, 1],
                             [1, 0, 0, 0, 0, 0, 0, 0],
                             [0, 1, 0, 0, 0, 0, 0, 0],
                             [0, 0, 1, 0, 0, 0, 0, 0],
                             [0, 0, 0, 1, 0, 0, 0, 0],
                             [0, 0, 0, 0, 1, 0, 0, 0],
                             [0, 0, 0, 0, 0, 1, 0, 0],
                             [0, 0, 0, 0, 0, 0, 1, 0]]
            LFSR3 = LinearLayer_CVL(matrix(GF(2), lfsr3_mat), name="LFSR3")

            lfsr_layer = WordSBoxCipher(s, 16, 16, name="lfsr_layer3")
            for j in range(2):  # Add LFSRs
                for i in range(4):
                    node_lfsr3 = lfsr_layer.add_subcipher(
                        LFSR3, [(lfsr_layer.IN, (4*j + i, 0))]
                    )
                    lfsr_layer.add_output([(node_lfsr3, (0, 4*j + i))])
            for j in range(2, 4):  # Connect the rest directly to output
                lfsr_layer.add_output(
                    [(lfsr_layer.IN, (4*j + i, 4*j + i)) for i in range(4)]
                )

            node_tk3 = tk3_schedule.add_subcipher(
                lfsr_layer, [(node_tk3_pt, (i, i)) for i in range(16)]
            )  # add LFSR layer
            tk3_schedule.add_output([(node_tk3, (i, i)) for i in range(16)])

        if z == 1:
            return [tk1_schedule]
        if z == 2:
            return [tk1_schedule, tk2_schedule]
        if z == 3:
            return [tk1_schedule, tk2_schedule, tk3_schedule]
        raise ValueError(
            f"{z = } is an invalid parameter for create_tk_schedules." # noqa
        )

    def __init__(self, n=64, t=64, R=None, key=None, name=None):
        r"""
        The civerly implementation of SKINNY. It takes the following
        arguments:

            - ``n`` -- integer; The block size of SKINNY. It is required that
              :math:`n \in \{ 64, 128 \}`.

            - ``t`` -- integer; The tweakey size of SKINNY. Needs to fulfill
              :math:`t \in \{ n, 2n, 3n \}`.

            - ``key`` -- integer (optional); The (tweak-)key value for SKINNY.
              If no key is specified, it is defaulted to 0.

            - ``name`` -- string (optional); The name of the SKINNY cipher.
              Is defaulted to "SKINNY".

        The test vectors used below are taken from SKINNYs original
        specification (https://eprint.iacr.org/2016/660.pdf):

        sage: from civerly.cipher_implementations.skinny import SKINNY_CVL
        sage: from civerly.util import int_to_vec, vec_to_int
        sage: skinny = SKINNY_CVL(
        ....:   64, 64, key=0xf5269826fc681238, name="SKINNY-64-64")
        sage: vec_to_int(skinny(int_to_vec(0x06034f957724d19d, 64))) == \
        ....:   0xbb39dfb2429b8ac7
        True
        sage: skinny = SKINNY_CVL(
        ....:   64, 128, key=0x9eb93640d088da63_76a39d1c8bea71e1,
        ....:   name="SKINNY-64-128")
        sage: vec_to_int(skinny(int_to_vec(0xcf16cfe8fd0f98aa, 64))) == \
        ....:   0x6ceda1f43de92b9e
        True
        sage: skinny = SKINNY_CVL(
        ....:    64, 192,
        ....:   key=0xed00c85b120d6861_8753e24bfd908f60_b2dbb41b422dfcd0,
        ....:   name="SKINNY-64-192")
        sage: vec_to_int(skinny(int_to_vec(0x530c61d35e8663c3, 64))) == \
        ....:   0xdd2cf1a8f330303c
        True
        sage: skinny = SKINNY_CVL(128, 128,
        ....:   key=0x4f55cfb0520cac52fd92c15f37073e93, name="SKINNY-128-128")
        sage: vec_to_int(skinny(int_to_vec(
        ....:   0xf20adb0eb08b648a3b2eeed1f0adda14, 128))) == \
        ....:   0x22ff30d498ea62d7e45b476e33675b74
        True
        sage: skinny = SKINNY_CVL(128, 256,
        ....:   key=0x009cec81605d4ac1d2ae9e3085d7a1f3_1ac123ebfc00fddcf01046ceeddfcab3,
        ....:   name="SKINNY-128-256")
        sage: vec_to_int(skinny(int_to_vec(
        ....:   0x3a0c47767a26a68dd382a695e7022e25, 128))) == \
        ....:   0xb731d98a4bde147a7ed4a6f16b9b587f
        True
        sage: skinny = SKINNY_CVL(128, 384,
        ....:   key=0xdf889548cfc7ea52d296339301797449_ab588a34a47f1ab2dfe9c8293fbea9a5_ab1afac2611012cd8cef952618c3ebe8,
        ....:   name="SKINNY-128-384")
        sage: vec_to_int(skinny(int_to_vec(
        ....:   0xa3994b66ad85a3459f44e92b08f550cb, 128))) == \
        ....:   0x94ecf589e2017c601b38c6346a10dcfa
        True

        TESTS::

            sage: from civerly.cipher_implementations.skinny import SKINNY_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: skinny = SKINNY_CVL(64, 64, name="branchnum-SKINNY-32")
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - scip
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.MILP,
            ....:     granularity=GRANULARITY.WORDWISE,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.BRANCH_NUMBER,
            ....:     milp_solver=SCIP_CVL(),
            ....:     path=Path(tmpdir))
            ....:   skinny.analyse(model_options)
            22752 variables and 23505 constraints were written to '...'
            32

            sage: from civerly.cipher_implementations.skinny import SKINNY_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: skinny = SKINNY_CVL(64, 64, R=10, name="wordwise-SKINNY-10")
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - scip
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.MILP,
            ....:     granularity=GRANULARITY.WORDWISE,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.GENERALIZED_WORDWISE,
            ....:     milp_solver=SCIP_CVL(),
            ....:     path=Path(tmpdir))
            ....:   skinny.analyse(model_options)
            7136 variables and 7361 constraints were written to '...'
            46

            sage: from civerly.cipher_implementations.skinny import SKINNY_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: skinny = SKINNY_CVL(64, 64, R=3, name="bitwise-SKINNY-3")
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - scip
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.MILP,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.MORE_DUMMIES,
            ....:     sbox_modeling=SBOX_MODELING.CONVEX_HULL,
            ....:     milp_solver=SCIP_CVL(),
            ....:     path=Path(tmpdir))
            ....:   skinny.analyse(model_options)
            9312 variables and 9585 constraints were written to '...'
            10

            sage: from civerly.cipher_implementations.skinny import SKINNY_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: skinny = SKINNY_CVL(64, 64, name="branchnum-SKINNY-32")
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - gurobi
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.MILP,
            ....:     granularity=GRANULARITY.WORDWISE,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.BRANCH_NUMBER,
            ....:     milp_solver=GUROBI_CVL(),
            ....:     path=Path(tmpdir))
            ....:   skinny.analyse(model_options)
            22752 variables and 23505 constraints were written to '...'
            32

            sage: from civerly.cipher_implementations.skinny import SKINNY_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: skinny = SKINNY_CVL(64, 64, R=10, name="wordwise-SKINNY-10")
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - gurobi
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.MILP,
            ....:     granularity=GRANULARITY.WORDWISE,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.GENERALIZED_WORDWISE,
            ....:     milp_solver=GUROBI_CVL(),
            ....:     path=Path(tmpdir))
            ....:   skinny.analyse(model_options)
            7136 variables and 7361 constraints were written to '...'
            46

            sage: from civerly.cipher_implementations.skinny import SKINNY_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: skinny = SKINNY_CVL(64, 64, R=3, name="bitwise-SKINNY-3")
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - gurobi
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.MILP,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.MORE_DUMMIES,
            ....:     sbox_modeling=SBOX_MODELING.CONVEX_HULL,
            ....:     milp_solver=GUROBI_CVL(),
            ....:     path=Path(tmpdir))
            ....:   skinny.analyse(model_options)
            9312 variables and 9585 constraints were written to '...'
            10

        Using SAT modeling::

            sage: from civerly.cipher_implementations.skinny import SKINNY_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - cryptominisat  # optional - espresso
            ....:   skinny = SKINNY_CVL(64, 64, R=3, name="bitwise-SKINNY-3")
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.EXCLUDE_ODD,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     sat_solver=CRYPTOMINISAT_CVL(),
            ....:     logic_minimizer=ESPRESSO_CVL(),
            ....:     solve_range=(10, 20),
            ....:     path=Path(tmpdir))
            ....:   skinny.analyse(model_options)
            8976 variables and 19553 clauses were written to '...'
            [ 10 , 20] (trying w =  15) : SAT
            [ 10 , 15] (trying w =  12) : SAT
            [ 10 , 12] (trying w =  11) : SAT
            [ 10 , 11] (trying w =  10) : SAT
            10

            sage: from civerly.cipher_implementations.skinny import SKINNY_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - cadical  # optional - espresso
            ....:   skinny = SKINNY_CVL(64, 64, R=3, name="bitwise-SKINNY-3")
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.EXCLUDE_ODD,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     sat_solver=CADICAL_CVL(),
            ....:     logic_minimizer=ESPRESSO_CVL(),
            ....:     solve_range=(10, 20),
            ....:     path=Path(tmpdir))
            ....:   skinny.analyse(model_options)
            8976 variables and 19553 clauses were written to '...'
            [ 10 , 20] (trying w =  15) : SAT
            [ 10 , 15] (trying w =  12) : SAT
            [ 10 , 12] (trying w =  11) : SAT
            [ 10 , 11] (trying w =  10) : SAT
            10

        Modeling linear cryptanalysis::

            sage: from civerly.cipher_implementations.skinny import SKINNY_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: skinny = SKINNY_CVL(64, 64, R=10, name="wordwise-SKINNY-10")
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - gurobi
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.LINEAR,
            ....:     optimization=OPTIMIZATION.MILP,
            ....:     granularity=GRANULARITY.WORDWISE,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.GENERALIZED_WORDWISE,
            ....:     milp_solver=GUROBI_CVL(),
            ....:     path=Path(tmpdir))
            ....:   skinny.analyse(model_options)
            7136 variables and 7521 constraints were written to '...'
            43

            sage: from civerly.cipher_implementations.skinny import SKINNY_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: skinny = SKINNY_CVL(64, 64, R=3, name="bitwise-SKINNY-3")
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - gurobi  # optional - espresso
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.LINEAR,
            ....:     optimization=OPTIMIZATION.MILP,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.MORE_DUMMIES,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     milp_solver=GUROBI_CVL(),
            ....:     logic_minimizer=ESPRESSO_CVL(),
            ....:     path=Path(tmpdir))
            ....:   skinny.analyse(model_options)
            9264 variables and 10161 constraints were written to '...'
            5

            sage: from civerly.cipher_implementations.skinny import SKINNY_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: skinny = SKINNY_CVL(64, 64, R=3, name="bitwise-SKINNY-3")
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - scip  # optional - espresso
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.LINEAR,
            ....:     optimization=OPTIMIZATION.MILP,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.MORE_DUMMIES,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     milp_solver=SCIP_CVL(),
            ....:     logic_minimizer=ESPRESSO_CVL(),
            ....:     path=Path(tmpdir))
            ....:   skinny.analyse(model_options)
            9264 variables and 10161 constraints were written to '...'
            5

            sage: from civerly.cipher_implementations.skinny import SKINNY_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - cryptominisat  # optional - espresso
            ....:   skinny = SKINNY_CVL(64, 64, R=3, name="bitwise-SKINNY-3")
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.LINEAR,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.EXCLUDE_ODD,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     sat_solver=CRYPTOMINISAT_CVL(),
            ....:     logic_minimizer=ESPRESSO_CVL(),
            ....:     solve_range=(4, 10),
            ....:     path=Path(tmpdir))
            ....:   skinny.analyse(model_options)
            8976 variables and 19313 clauses were written to '...'
            [  4 , 10] (trying w =   7) : SAT
            [  4 ,  7] (trying w =   5) : SAT
            [  4 ,  5] (trying w =   4) : UNSAT
            5

            sage: from civerly.cipher_implementations.skinny import SKINNY_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - cadical  # optional - espresso
            ....:   skinny = SKINNY_CVL(64, 64, R=3, name="bitwise-SKINNY-3")
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.LINEAR,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.EXCLUDE_ODD,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     sat_solver=CADICAL_CVL(),
            ....:     logic_minimizer=ESPRESSO_CVL(),
            ....:     solve_range=(4, 10),
            ....:     path=Path(tmpdir))
            ....:   skinny.analyse(model_options)
            8976 variables and 19313 clauses were written to '...'
            [  4 , 10] (trying w =   7) : SAT
            [  4 ,  7] (trying w =   5) : SAT
            [  4 ,  5] (trying w =   4) : UNSAT
            5

        """
        assert n in [64, 128], (
            f"The block size of SKINNY can only be 64 or 128, not {n}!"
        )
        assert t in [n, 2*n, 3*n], (
            f"The tweakey size of SKINNY can only be {n}, {2*n} or {3*n}, "
            f"but not {t}!"
        )

        z = t // n

        if key is None:
            key = 0
        if name is None:
            name = "SKINNY"

        round_dict = {
            (64, 64): 32, (64, 128): 36, (64, 192): 40,
            (128, 128): 40, (128, 256): 48, (128, 384): 56
        }

        if R is None:
            R = round_dict[(n, t)]  # For full-round versions

        s = n // 16  # wordsize

        # SubCells
        # ------------------------------------------------------------
        subcells = AESlike(s, rows=4, cols=4, name="SubCells")

        if s == 4:
            sbox = SBox_CVL(SBox([
                0xc, 0x6, 0x9, 0x0, 0x1, 0xa, 0x2, 0xb,
                0x3, 0x8, 0x5, 0xd, 0x4, 0xe, 0x7, 0xf
            ]), name="S4")
        else:
            s8_arr = [
                0x65, 0x4c, 0x6a, 0x42, 0x4b, 0x63, 0x43, 0x6b, 0x55,
                0x75, 0x5a, 0x7a, 0x53, 0x73, 0x5b, 0x7b, 0x35, 0x8c,
                0x3a, 0x81, 0x89, 0x33, 0x80, 0x3b, 0x95, 0x25, 0x98,
                0x2a, 0x90, 0x23, 0x99, 0x2b, 0xe5, 0xcc, 0xe8, 0xc1,
                0xc9, 0xe0, 0xc0, 0xe9, 0xd5, 0xf5, 0xd8, 0xf8, 0xd0,
                0xf0, 0xd9, 0xf9, 0xa5, 0x1c, 0xa8, 0x12, 0x1b, 0xa0,
                0x13, 0xa9, 0x05, 0xb5, 0x0a, 0xb8, 0x03, 0xb0, 0x0b,
                0xb9, 0x32, 0x88, 0x3c, 0x85, 0x8d, 0x34, 0x84, 0x3d,
                0x91, 0x22, 0x9c, 0x2c, 0x94, 0x24, 0x9d, 0x2d, 0x62,
                0x4a, 0x6c, 0x45, 0x4d, 0x64, 0x44, 0x6d, 0x52, 0x72,
                0x5c, 0x7c, 0x54, 0x74, 0x5d, 0x7d, 0xa1, 0x1a, 0xac,
                0x15, 0x1d, 0xa4, 0x14, 0xad, 0x02, 0xb1, 0x0c, 0xbc,
                0x04, 0xb4, 0x0d, 0xbd, 0xe1, 0xc8, 0xec, 0xc5, 0xcd,
                0xe4, 0xc4, 0xed, 0xd1, 0xf1, 0xdc, 0xfc, 0xd4, 0xf4,
                0xdd, 0xfd, 0x36, 0x8e, 0x38, 0x82, 0x8b, 0x30, 0x83,
                0x39, 0x96, 0x26, 0x9a, 0x28, 0x93, 0x20, 0x9b, 0x29,
                0x66, 0x4e, 0x68, 0x41, 0x49, 0x60, 0x40, 0x69, 0x56,
                0x76, 0x58, 0x78, 0x50, 0x70, 0x59, 0x79, 0xa6, 0x1e,
                0xaa, 0x11, 0x19, 0xa3, 0x10, 0xab, 0x06, 0xb6, 0x08,
                0xba, 0x00, 0xb3, 0x09, 0xbb, 0xe6, 0xce, 0xea, 0xc2,
                0xcb, 0xe3, 0xc3, 0xeb, 0xd6, 0xf6, 0xda, 0xfa, 0xd3,
                0xf3, 0xdb, 0xfb, 0x31, 0x8a, 0x3e, 0x86, 0x8f, 0x37,
                0x87, 0x3f, 0x92, 0x21, 0x9e, 0x2e, 0x97, 0x27, 0x9f,
                0x2f, 0x61, 0x48, 0x6e, 0x46, 0x4f, 0x67, 0x47, 0x6f,
                0x51, 0x71, 0x5e, 0x7e, 0x57, 0x77, 0x5f, 0x7f, 0xa2,
                0x18, 0xae, 0x16, 0x1f, 0xa7, 0x17, 0xaf, 0x01, 0xb2,
                0x0e, 0xbe, 0x07, 0xb7, 0x0f, 0xbf, 0xe2, 0xca, 0xee,
                0xc6, 0xcf, 0xe7, 0xc7, 0xef, 0xd2, 0xf2, 0xde, 0xfe,
                0xd7, 0xf7, 0xdf, 0xff
            ]
            sbox = SBox_CVL(SBox(s8_arr), name="S8")

        for i in range(16):
            node = subcells.add_subcipher(sbox, [(subcells.IN, (i, 0))])
            subcells.add_output([(node, (0, i))])
        # ------------------------------------------------------------

        # AddConstants
        # ------------------------------------------------------------
        addconstants = AESlike(s, rows=4, cols=4, name="AddConstants")
        xor_consts = RoundkeyXOR_CVL(3*s, const=0, name="XORconstants")
        node_xorconst = addconstants.add_subcipher(
            xor_consts, [(addconstants.IN, (4*i, i)) for i in range(3)]
        )
        addconstants.add_output([(node_xorconst, (i, 4*i)) for i in range(3)])

        node_I = addconstants.add_subcipher(
            I_CVL(13*s, name="I"),
            [
                (addconstants.IN, (i, i - 1 - i//4 + i//12))
                for i in range(16) if i not in [0, 4, 8]
            ]
        )
        addconstants.add_output([
            (node_I, (i - 1 - i//4 + i//12, i))
            for i in range(16) if i not in [0, 4, 8]
        ])
        # ------------------------------------------------------------

        # AddRoundTweakey
        # ------------------------------------------------------------
        addroundtweakey = AESlike(s, rows=4, cols=4, name="AddRoundTweakey")
        atk1 = RoundkeyXOR_CVL(4*s, const=0, name="atk1")
        atk2 = RoundkeyXOR_CVL(4*s, const=0, name="atk2")

        node_atk1 = addroundtweakey.add_subcipher(
            atk1, [(addroundtweakey.IN, (i, i)) for i in range(4)]
        )
        node_atk2 = addroundtweakey.add_subcipher(
            atk2, [(addroundtweakey.IN, (i + 4, i)) for i in range(4)]
        )

        node_I2 = addroundtweakey.add_subcipher(
            I_CVL(8*s, name="I"),
            [(addroundtweakey.IN, (i + 8, i)) for i in range(8)]
        )
        addroundtweakey.add_output([(node_I2, (i, i + 8)) for i in range(8)])
        addroundtweakey.add_output([(node_atk1, (i, i)) for i in range(4)])
        addroundtweakey.add_output([(node_atk2, (i, i + 4)) for i in range(4)])
        # ------------------------------------------------------------

        # ShiftRows
        # ------------------------------------------------------------
        shiftrows = PermuteLayer_CVL(perm=[
            0, 1, 2, 3, 7, 4, 5, 6, 10, 11, 8, 9, 13, 14, 15, 12
        ], word_coarseness=s, name="ShiftRows").inv()
        # ------------------------------------------------------------

        # MixColumns
        # ------------------------------------------------------------
        mixcolumns = AESlike(s, rows=4, cols=4, name="MixColumns")

        I = identity_matrix(GF(2), s)  # noqa: E741
        O = zero_matrix(GF(2), s)  # noqa: E741

        matrix_mc = [[I, O, I, I],
                     [I, O, O, O],
                     [O, I, I, O],
                     [I, O, I, O]]

        mc = LinearLayer_CVL(block_matrix(GF(2), matrix_mc, subdivide=False),
                             branch_number_differential=2, name="MC")

        for j in range(4):
            node = mixcolumns.add_subcipher(
                mc, [(mixcolumns.IN, (i+4*j, i)) for i in range(4)]
            )
            mixcolumns.add_output([(node, (i, i+4*j)) for i in range(4)])
        # ------------------------------------------------------------
        # Transpose for correct alignment
        TR = PermuteLayer_CVL(perm=[
            0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15
        ], word_coarseness=s, name="Transpose")

        skinny_round = AESlike(s, rows=4, cols=4, name="SKINNY-round")

        node_round = skinny_round.add_subcipher(
            subcells, [(skinny_round.IN, (i, i)) for i in range(16)]
        )
        node_round_const = skinny_round.add_subcipher(
            addconstants, [(node_round, (i, i)) for i in range(16)]
        )
        node_round_tweakey = skinny_round.add_subcipher(
            addroundtweakey, [(node_round_const, (i, i)) for i in range(16)]
        )
        node_round = skinny_round.add_subcipher(
            shiftrows, [(node_round_tweakey, (i, i)) for i in range(16)]
        )

        node_round = skinny_round.add_subcipher(
            TR, [(node_round, (i, i)) for i in range(16)]
        )  # Transpose
        node_round = skinny_round.add_subcipher(
            mixcolumns, [(node_round, (i, i)) for i in range(16)]
        )
        node_round = skinny_round.add_subcipher(
            TR, [(node_round, (i, i)) for i in range(16)]
        )  # Transpose

        skinny_round.add_output([(node_round, (i, i)) for i in range(16)])

        skinny_cipher = AESlike(s, rows=4, cols=4, name=name)

        # array of tk-schedule ciphers
        tk_schedules = SKINNY_CVL.create_tk_schedules(s, z)

        # divide up the key into [TK1, TK2, TK3]
        current_tweakeys = [
            (key >> (y*n)) & ((1 << n) - 1) for y in range(z)
        ][::-1]
        final_tweakeys = [0 for _ in range(R)]
        for r in range(R):
            for w in range(z):
                final_tweakeys[r] ^= current_tweakeys[w]
            current_tweakeys = [
                vec_to_int(tk_schedules[w](
                    int_to_vec(current_tweakeys[w], n)
                ))
                for w in range(z)
            ]  # Update tweakeys with the respective tk-schedule

        node_cipher = skinny_cipher.IN
        for r in range(R):
            # Set roundconstant values
            # ---------------------------------------------
            # Compute (c0, c1, c2) from the round constants
            current_constant = ((SKINNY_CVL.consts[r] & 0xf) << (2*s)) \
                | (((SKINNY_CVL.consts[r] >> 4) & 0x3) << s) \
                | 0x2
            skinny_round.nodes[node_round_const].nodes[node_xorconst].const = \
                current_constant
            # ---------------------------------------------

            # Set roundtweakey values
            # ---------------------------------------------
            skinny_round.nodes[node_round_tweakey].nodes[node_atk1].const = \
                (final_tweakeys[r] >> (3*4*s)) & ((1 << (4*s)) - 1)
            skinny_round.nodes[node_round_tweakey].nodes[node_atk2].const = \
                (final_tweakeys[r] >> (2*4*s)) & ((1 << (4*s)) - 1)
            # ---------------------------------------------

            node_cipher = skinny_cipher.add_subcipher(
                skinny_round, [(node_cipher, (i, i)) for i in range(16)]
            )

        skinny_cipher.add_output([(node_cipher, (i, i)) for i in range(16)])

        self.skinny_cipher = skinny_cipher

    def __new__(cls, *args, **kwargs):
        instance = super(SKINNY_CVL, cls).__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.skinny_cipher
