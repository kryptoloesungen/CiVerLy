from civerly.wordsboxcipher import WordSBoxCipher
from civerly.component import SBox_CVL, PermuteLayer_CVL, RoundkeyXOR_CVL
from sage.crypto.sboxes import PRESENT as present_S


class PRESENT_CVL:
    def __init__(self, R=31, rks=[], name=None):
        r"""
        The CiVerLy implementation of PRESENT. It takes in the following
        arguments:

            - ``R`` -- integer; Number of rounds.

            - ``rks`` -- list (optional); Specifies the roundkey values of
              PRESENT, in order to being able to properly test the
              implementation. Is required to have length :math:`R+1`, and
              defaults to ``[0, ..., 0]``.

            - ``name`` -- string (optional); The name of the cipher.
              Will be used to name the cipher and the corresponding files
              generated (such as the reports and cipher graphs).

        This cipher is "plug-and-play" usable, i.e. it can be directly used
        when imported.

        EXAMPLES:

        Encrypt a message (for verifying the implemenation)::

            sage: from civerly.cipher_implementations.present \
            ....:   import PRESENT_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: present_cipher = PRESENT_CVL(R=10)
            sage: hex(vec_to_int(present_cipher(int_to_vec(0xabcd1234, 64))))
            '0xdd9e25f5bd58fdc9'

        Since PRESENT is a word-based cipher, we can perform
        branch-number-based wordwise modeling::

            sage: from civerly.cipher_implementations.present \
            ....:   import PRESENT_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: present_cipher = PRESENT_CVL(R=4)
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - scip
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.MILP,
            ....:     granularity=GRANULARITY.WORDWISE,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.BRANCH_NUMBER,
            ....:     milp_solver=SOLVER.SCIP,
            ....:     path=Path(tmpdir))
            ....:   present_cipher.analyse(model_options)
            1284 variables and 1341 constraints were written to '...'
            4

        Of course, since the branch number of any word-permutation is 2, this
        result is not very interesting and unprecise, as the optimal solution
        here would be one active word per round, which is specifically avoided
        to be possible in PRESENT. This indicates that generalized wordwise
        modeling might be a more reasonable approach. However, performing
        generalized wordwise modeling is extremely costly since we would need
        to iterate over :math:`2^{2n}` possible transition, for a linear layer
        transforming :math:`n` words. For :math:`n = 16`, as is the case for
        PRESENT, this results in an infeasibly complex task, which takes an
        unproportionally long time to perform. Note that this is due to the
        fact that generalized wordwise modeling ignores the fact that this
        current linear layer is actually a word-permutation, which would, in
        theory, be significantly easier to model. In turn, this also means
        that the complexity of modeling this permutation using generalized
        wordwise modeling is equal to the complexity of modeling **any**
        linear layer acting on 16 words.

        However, the bitwise modeling technique does not come with such issues
        and is also more precise, since the result will be an actually possible
        differential (or linear) trail instead of an activity pattern of the
        words. As the linear layer of \cipher{PRESENT} is a bit permutation and
        therefore trivial to model, we do not need to specify a linear layer
        modeling technique::

            sage: from civerly.cipher_implementations.present \
            ....:   import PRESENT_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: present_cipher = PRESENT_CVL(R=4)
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - scip
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.MILP,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.CONVEX_HULL,
            ....:     milp_solver=SOLVER.SCIP,
            ....:     path=Path(tmpdir))
            ....:   present_cipher.analyse(model_options)
            5312 variables and 6081 constraints were written to '...'
            12

        Here, the analysis output 12 means that the best differential trail
        over 4 rounds of PRESENT has a probability of :math:`2^{-12}`.


        TESTS::

            sage: rks = [
            ....:   0x0000000000000000, 0xc000000000000000, 0x5000180000000001,
            ....:   0x60000a0003000001, 0xb0000c0001400062, 0x900016000180002a,
            ....:   0x0001920002c00033, 0xa000a0003240005b, 0xd000d4001400064c,
            ....:   0x30017a001a800284, 0xe01926002f400355, 0xf00a1c0324c005ed,
            ....:   0x800d5e014380649e, 0x4017b001abc02876, 0x71926802f600357f,
            ....:   0x10a1ce324d005ec7, 0x20d5e21439c649a8, 0xc17b041abc428730,
            ....:   0xc926b82f60835781, 0x6a1cd924d705ec19, 0xbd5e0d439b249aea,
            ....:   0x07b077abc1a8736e, 0x426ba0f60ef5783e, 0x41cda84d741ec1d5,
            ....:   0xf5e0e839b509ae8f, 0x2b075ebc1d0736ad, 0x86ba2560ebd783ad,
            ....:   0x8cdab0d744ac1d77, 0x1e0eb19b561ae89b, 0xd075c3c1d6336acd,
            ....:   0x8ba27a0eb8783ac9, 0x6dab31744f41d700
            ....: ]
            sage: from civerly.cipher_implementations.present \
            ....:   import PRESENT_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: present_cipher = PRESENT_CVL(R=31,rks=rks)
            sage: vec_to_int(present_cipher(int_to_vec(0x0, 64))) \
            ....:   == 0x5579C138_7B228445
            True

        Model the cipher with MILP:

            sage: from civerly.cipher_implementations.present \
            ....:   import PRESENT_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: present_cipher = PRESENT_CVL(R=4)
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - gurobi
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.MILP,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.CONVEX_HULL,
            ....:     milp_solver=SOLVER.GUROBI,
            ....:     path=Path(tmpdir))
            ....:   present_cipher.analyse(model_options)
            ....:   present_cipher.generate_report(model_options)
            5312 variables and 6081 constraints were written to '...'
            12
            Output file in: ...

            sage: from civerly.cipher_implementations.present \
            ....:   import PRESENT_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: present_cipher = PRESENT_CVL(R=4)
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - gurobi  # optional - espresso
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.MILP,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     milp_solver=SOLVER.GUROBI,
            ....:     logic_minimizer=SOLVER.ESPRESSO,
            ....:     path=Path(tmpdir))
            ....:   present_cipher.analyse(model_options)
            ....:   present_cipher.generate_report(model_options)
            5312 variables and 8641 constraints were written to '...'
            12
            Output file in: ...

            sage: from civerly.cipher_implementations.present \
            ....:   import PRESENT_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: present_cipher = PRESENT_CVL(R=4)
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - gurobi  # long
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.MILP,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.DISTORTED_BALL,
            ....:     milp_solver=SOLVER.GUROBI,
            ....:     path=Path(tmpdir))
            ....:   present_cipher.analyse(model_options)
            ....:   present_cipher.generate_report(model_options)
            5312 variables and 6977 constraints were written to '...'
            12
            Output file in: ...

        Model the cipher with SAT:

            sage: from civerly.cipher_implementations.present \
            ....:   import PRESENT_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - cryptominisat  # optional - espresso
            ....:   present_cipher = PRESENT_CVL(R=4)
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.EXCLUDE_ODD,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     sat_solver=SOLVER.CRYPTOMINISAT,
            ....:     logic_minimizer=SOLVER.ESPRESSO,
            ....:     path=Path(tmpdir))
            ....:   present_cipher.analyse(model_options)
            ....:   trail = str(present_cipher.get_trail(model_options))
            ....:   assert "Unnamed Component" not in trail
            5312 variables and 13441 clauses were written to '...'
            12

            sage: from civerly.cipher_implementations.present \
            ....:   import PRESENT_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - cadical  # optional - espresso
            ....:   present_cipher = PRESENT_CVL(R=4)
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.EXCLUDE_ODD,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     sat_solver=SOLVER.CADICAL,
            ....:     logic_minimizer=SOLVER.ESPRESSO,
            ....:     path=Path(tmpdir))
            ....:   present_cipher.analyse(model_options)
            ....:   trail = str(present_cipher.get_trail(model_options))
            ....:   assert "Unnamed Component" not in trail
            5312 variables and 13441 clauses were written to '...'
            12

        Linear cryptanalysis::

            sage: from civerly.cipher_implementations.present \
            ....:   import PRESENT_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - cryptominisat  # optional - espresso
            ....:   present_cipher = PRESENT_CVL(R=4)
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.LINEAR,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.EXCLUDE_ODD,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     sat_solver=SOLVER.CRYPTOMINISAT,
            ....:     logic_minimizer=SOLVER.ESPRESSO,
            ....:     path=Path(tmpdir))
            ....:   present_cipher.analyse(model_options)
            ....:   trail = str(present_cipher.get_trail(model_options))
            ....:   assert "Unnamed Component" not in trail
            5312 variables and 12993 clauses were written to '...'
            6

            sage: from civerly.cipher_implementations.present \
            ....:   import PRESENT_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - cryptominisat  # optional - espresso
            ....:   present_cipher = PRESENT_CVL(R=4)
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.LINEAR,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.MORE_DUMMIES,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     sat_solver=SOLVER.CRYPTOMINISAT,
            ....:     logic_minimizer=SOLVER.ESPRESSO,
            ....:     path=Path(tmpdir))
            ....:   present_cipher.analyse(model_options)
            5312 variables and 12993 clauses were written to '...'
            6

            sage: from civerly.cipher_implementations.present \
            ....:   import PRESENT_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - cryptominisat  # optional - espresso
            ....:   present_cipher = PRESENT_CVL(R=5)
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.LINEAR,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.EXCLUDE_ODD,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     sat_solver=SOLVER.CRYPTOMINISAT,
            ....:     logic_minimizer=SOLVER.ESPRESSO,
            ....:     path=Path(tmpdir))
            ....:   present_cipher.analyse(model_options)
            ....:   trail = str(present_cipher.get_trail(model_options))
            ....:   assert "Unnamed Component" not in trail
            6512 variables and 16017 clauses were written to '...'
            8
        """
        if name is None:
            name = "PRESENT"

        if rks == []:
            rks = [0 for _ in range(R + 1)]  # set roundkeys = 0 as default
        s = SBox_CVL(present_S, name="SBox")

        # sboxlayer is an SBoxCipher, containing the sbox components
        # SBox_CVL 16 times in parallel.
        sboxlayer = WordSBoxCipher(4, 16, 16, name="SBoxLayer")
        for j in range(16):
            node = sboxlayer.add_subcipher(s, [(sboxlayer.IN, (j, 0))])
            sboxlayer.add_output([(node, (0, j))])

        # PRESENT permutation layer
        permutation = PermuteLayer_CVL(
            [
                0,
                16,
                32,
                48,
                1,
                17,
                33,
                49,
                2,
                18,
                34,
                50,
                3,
                19,
                35,
                51,
                4,
                20,
                36,
                52,
                5,
                21,
                37,
                53,
                6,
                22,
                38,
                54,
                7,
                23,
                39,
                55,
                8,
                24,
                40,
                56,
                9,
                25,
                41,
                57,
                10,
                26,
                42,
                58,
                11,
                27,
                43,
                59,
                12,
                28,
                44,
                60,
                13,
                29,
                45,
                61,
                14,
                30,
                46,
                62,
                15,
                31,
                47,
                63,
            ],
            name="Permutation",
        )

        # NOTE: This is an alternative component to the RK_CVL. Instead
        # of seperating the key addition into a "factory" component that
        # outputs the key, and an XOR addition, it makes more sense to combine
        # them to a component, which is the RoundkeyXOR_CVL component.
        # It eases the implementation in several aspects (such as modeling and
        # graph traversal).
        key_add = RoundkeyXOR_CVL(64, 0x0, name="KeyAdd")

        # Implementation of the PRESENT round.
        # ------------------------------------------------ #
        present_round = WordSBoxCipher(4, 16, 16, name="present_round")
        node_rk = present_round.add_subcipher(
            key_add, [(present_round.IN, (i, i)) for i in range(16)]
        )
        node = present_round.add_subcipher(
            sboxlayer, [(node_rk, (i, i)) for i in range(16)]
        )
        node = present_round.add_subcipher(
            permutation, [(node, (i, i)) for i in range(16)]
        )
        present_round.add_output([(node, (i, i)) for i in range(16)])
        # ------------------------------------------------ #

        # Implementation of the PRESENT cipher.
        # ------------------------------------------------ #
        present_cipher = WordSBoxCipher(4, 16, 16, name=name)
        cipher_node = present_cipher.IN
        for r in range(R):
            present_round.nodes[node_rk].const = rks[r]
            cipher_node = present_cipher.add_subcipher(
                present_round, [(cipher_node, (i, i)) for i in range(16)]
            )

        key_add.const = rks[R]

        cipher_node = present_cipher.add_subcipher(
            key_add, [(cipher_node, (i, i)) for i in range(16)]
        )
        present_cipher.add_output([(cipher_node, (i, i)) for i in range(16)])
        # ------------------------------------------------ #

        self.present_cipher = present_cipher

    def __new__(cls, *args, **kwargs):
        instance = super(PRESENT_CVL, cls).__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.present_cipher
