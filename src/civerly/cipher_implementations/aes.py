r"""
Implementation of the AES.

Arguably, the AES is the most important cipher in the world. Hence, we use it
to exemplary describe the usage of CiVerLy.

EXAMPLES:

First, we want to determine the number of active S-boxes in 10-round AES. We
use a word-wise model based on the branch number. The full list of options is
given in :class:`civerly.model_options.MODEL_OPTIONS`::

    sage: from civerly.cipher_implementations.aes import AES_CVL
    sage: from civerly.model_options import *
    sage: import tempfile
    sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - scip
    ....:   aes = AES_CVL(R=10)
    ....:   model_options = MODEL_OPTIONS(
    ....:       cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
    ....:       optimization=OPTIMIZATION.MILP,
    ....:       granularity=GRANULARITY.WORDWISE,
    ....:       linear_layer_modeling=LINEAR_LAYER_MODELING.BRANCH_NUMBER,
    ....:       milp_solver=SCIP_CVL(),
    ....:       path=Path(tmpdir))
    ....:   aes.analyse(model_options)
    3236 variables and 3437 constraints were written to '...'
    55

Indeed, there are 55 active S-boxes for 10-round AES. Next up, we want to
study linear cryptanalysis using the more accurate modeling of MixColumn, which
requires solving a MILP itself::

    sage: from civerly.cipher_implementations.aes import AES_CVL
    sage: from civerly.model_options import *
    sage: import tempfile
    sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - scip
    ....:   aes = AES_CVL(R=10)
    ....:   model_options = MODEL_OPTIONS(
    ....:       cryptanalysis=CRYPTANALYSIS.LINEAR,
    ....:       optimization=OPTIMIZATION.MILP,
    ....:       granularity=GRANULARITY.WORDWISE,
    ....:       linear_layer_modeling=LINEAR_LAYER_MODELING.GENERALIZED_WORDWISE,
    ....:       milp_solver=SCIP_CVL(),
    ....:       path=Path(tmpdir))
    ....:   aes.analyse(model_options)
    3200 variables and 3329 constraints were written to '...'
    55

Notice that above we use the ``analyse`` function of the ``aes`` cipher.
While this is rather convenient, it requires the specified solver to be
installed on the same machine as CiVerLy. However, (for more complex
models) you might want to solve the models on a different, more
powerful machine. We adapt the example from above for this case. First,
we again define the cipher and the ``model_options``::

    sage: from civerly.cipher_implementations.aes import AES_CVL
    sage: from civerly.model_options import *
    sage: from pathlib import Path
    sage: aes = AES_CVL(R=10)
    sage: model_options = MODEL_OPTIONS(
    ....:     cryptanalysis=CRYPTANALYSIS.LINEAR,
    ....:     optimization=OPTIMIZATION.MILP,
    ....:     granularity=GRANULARITY.WORDWISE,
    ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.GENERALIZED_WORDWISE,
    ....:     path=Path("./DOCTEST-AES-Models/"))

As we rely on an external solver, we can simply put it to ``None`` in the
``model_options``. Next, we generate the model::

    sage: aes.model(model_options)
    LinearLayer MILP has been written to
    DOCTEST-AES-Models/MixColumn51845.mps.
    In order to continue the modeling, solve the generated MILP by providing a
    solution file with the name DOCTEST-AES-Models/MixColumn51845.sol.

As the output states, you have to provide a solution to the MILP for
MixColumn to continue the modeling. You would copy the ``.mps`` file to
a machine with a supported MILP solver, solve it and copy the ``.sol``
to the location specified above. As we cannot execute that step here,
we simulate it to continue::

    sage: # optional - scip
    sage: from pathlib import Path
    sage: input_file_name = Path("DOCTEST-AES-Models/MixColumn51845.mps")
    sage: output_file_name = Path("DOCTEST-AES-Models/MixColumn51845.sol")
    sage: SCIP_CVL().solve(input_file_name, output_file_name)

Notice that you do not have to keep the sage session alive while you
solve the model externally. Again, this is something we have to
simulate here, by simply deleting the ``aes`` and ``model_options`` objects::

    sage: del aes
    sage: del model_options

Next, we finish the model::

    sage: # optional - scip
    sage: from civerly.cipher_implementations.aes import AES_CVL
    sage: from civerly.model_options import *
    sage: from pathlib import Path
    sage: aes = AES_CVL(R=10)
    sage: model_options = MODEL_OPTIONS(
    ....:     cryptanalysis=CRYPTANALYSIS.LINEAR,
    ....:     optimization=OPTIMIZATION.MILP,
    ....:     granularity=GRANULARITY.WORDWISE,
    ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.GENERALIZED_WORDWISE,
    ....:     path=Path("./DOCTEST-AES-Models/"))
    sage: aes.model(model_options)
    Using existing file DOCTEST-AES-Models/MixColumn51845.sol,
    make sure it is up to date!
    3200 variables and 3329 constraints were written to
    'DOCTEST-AES-Models/AES.mps'
    Boolean Program (minimization, 3200 variables, 3329 constraints)

Now, you would again copy the ``.mps`` file, this time of course the
``AES.mps``, to a machine with a supported solver. After solving, the
solver will already tell you, that the objective value is 55. For
generating a report, you would copythe ``AES.sol`` file to the
``DOCTEST-AES-Models`` directory. Again, we have to simulate this::

    sage: # optional - scip
    sage: from pathlib import Path
    sage: SCIP_CVL().solve(input_file_name=Path("DOCTEST-AES-Models/AES.mps"),
    ....:       output_file_name=Path("DOCTEST-AES-Models/AES.sol")
    ....: )

And again, we simulate restarting CiVerLy::

    sage: # optional - scip
    sage: del aes
    sage: del model_options

Now, we first verify that the objective value is indeed 55::

    sage: # optional - scip
    sage: from civerly.cipher_implementations.aes import AES_CVL
    sage: from civerly.model_options import *
    sage: from pathlib import Path
    sage: sol_file_name = Path("DOCTEST-AES-Models/AES.sol")
    sage: SCIP_CVL().process_solution_file(sol_file_name)[1]
    55

Which tells us that there are indeed 55 active S-boxes. To visualize
the corresponding activity pattern, we can generate a PDF report::

    sage: from civerly.cipher_implementations.aes import AES_CVL
    sage: from civerly.model_options import *
    sage: from pathlib import Path
    sage: aes = AES_CVL(R=10)
    sage: model_options = MODEL_OPTIONS(
    ....:     cryptanalysis=CRYPTANALYSIS.LINEAR,
    ....:     optimization=OPTIMIZATION.MILP,
    ....:     granularity=GRANULARITY.WORDWISE,
    ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.GENERALIZED_WORDWISE,
    ....:     path=Path("./DOCTEST-AES-Models/"))
    sage: aes.generate_report(model_options) # optional - scip
    Output file in: DOCTEST-AES-Models/AES.pdf

To conclude our example, we remove the generated files::

    sage: import shutil
    sage: shutil.rmtree("DOCTEST-AES-Models", ignore_errors=True)
"""
from civerly.aeslike import AESlike
from civerly.component import (
    SBox_CVL, PermuteLayer_CVL, LinearLayer_CVL,
    RoundkeyXOR_CVL, ConstXOR_CVL, XOR_CVL,
)
from civerly.sboxcipher import SBoxCipher
from civerly.keyschedule import KeySchedule

from sage.matrix.constructor import Matrix as matrix
from sage.rings.finite_rings.finite_field_constructor import GF
from sage.matrix.special import identity_matrix, block_matrix
from sage.crypto.sboxes import AES as AES_S


class AES_KeySchedule_CVL(KeySchedule):
    def __init__(self, R):
        r"""
        AES-128 key schedule as a CiVerLy DAG.

        Takes a 128-bit master key and expands it into R+1 round keys
        following NIST FIPS 197.

        INPUT:

            - ``R`` -- integer; Number of rounds (1..10 for AES-128).

        EXAMPLES::

            sage: from civerly.cipher_implementations.aes import AES_KeySchedule_CVL
            sage: ks = AES_KeySchedule_CVL(10)
            sage: rks = ks(0x000102030405060708090a0b0c0d0e0f)
            sage: hex(rks[0])
            '0x102030405060708090a0b0c0d0e0f'
            sage: hex(rks[1])
            '0xd6aa74fdd2af72fadaa678f1d6ab76fe'
            sage: hex(rks[10])
            '0x13111d7fe3944a17f307a78b4d2b30c5'

        TESTS:

        Full key schedule against FIPS 197, Appendix C.1. k_sch outputs
        (key = ``000102030405060708090a0b0c0d0e0f``)::

            sage: from civerly.cipher_implementations.aes import AES_KeySchedule_CVL
            sage: ks = AES_KeySchedule_CVL(10)
            sage: rks = ks(0x000102030405060708090a0b0c0d0e0f)
            sage: for rk in rks:
            ....:     print(f'{rk:032x}')
            000102030405060708090a0b0c0d0e0f
            d6aa74fdd2af72fadaa678f1d6ab76fe
            b692cf0b643dbdf1be9bc5006830b3fe
            b6ff744ed2c2c9bf6c590cbf0469bf41
            47f7f7bc95353e03f96c32bcfd058dfd
            3caaa3e8a99f9deb50f3af57adf622aa
            5e390f7df7a69296a7553dc10aa31f6b
            14f9701ae35fe28c440adf4d4ea9c026
            47438735a41c65b9e016baf4aebf7ad2
            549932d1f08557681093ed9cbe2c974e
            13111d7fe3944a17f307a78b4d2b30c5
        """
        super().__init__(128, (R + 1) * 128, name="AES-KeySchedule")

        # Rcon[1..13] for up to 13 AES-128 expansion rounds.
        Rcon = [
            0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
            0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000,
            0x6c000000, 0xd8000000, 0xab000000,
        ]

        output_edges = [(self.IN, (i, i)) for i in range(128)]
        node = self.IN
        for r in range(R):
            node = self.add_subcipher(
                self._make_ks_step(Rcon[r]),
                [(node, (i, i)) for i in range(128)],
            )
            output_edges += [(node, (i, i + 128 * (r + 1))) for i in range(128)]

        self.add_output(output_edges)

    def __call__(self, k):
        r"""
        Expand master key ``k`` into a list of R+1 round-key integers.

        INPUT:

            - ``k`` -- integer; 128-bit master key.

        OUTPUT: List of R+1 integers.
        """
        from civerly.util import int_to_vec, vec_to_int
        n = self.input_length
        bits = self.eval(int_to_vec(k, n))
        return [vec_to_int(bits[i*n:(i+1)*n]) for i in range(self.output_length // n)]

    @staticmethod
    def _make_ks_step(rcon_val):
        """One AES-128 key-expansion step as a SBoxCipher(128 -> 128).

        Takes the current 128-bit key word [w0|w1|w2|w3] and outputs the
        next 128-bit key [new_w0|new_w1|new_w2|new_w3]:

            g = ConstXOR(SubWord(RotWord(w3)), rcon_val)
            new_w0 = w0 ^ g
            new_w1 = w1 ^ new_w0
            new_w2 = w2 ^ new_w1
            new_w3 = w3 ^ new_w2
        """
        step = SBoxCipher(128, 128, name="KS-step")

        # RotWord: cyclic left-shift of w3 (bits 96-127) by one byte.
        # In MSB-first, RotWord([B0,B1,B2,B3]) -> [B1,B2,B3,B0].
        # PermuteLayer_CVL convention: perm[i]=j means input bit i -> output bit j.
        # Input byte b (bits 8b..8b+7) lands at output byte (b-1)%4, so
        # input bit i goes to output bit (i-8)%32.
        rot_perm = [(i - 8) % 32 for i in range(32)]
        node_rot = step.add_subcipher(
            PermuteLayer_CVL(rot_perm, name="RotWord"),
            [(step.IN, (96 + i, i)) for i in range(32)],
        )

        # SubWord: apply AES S-box to each byte of the rotated word.
        sb_nodes = [
            step.add_subcipher(
                SBox_CVL(AES_S, name=f"SubWord_S{b}"),
                [(node_rot, (8*b + i, i)) for i in range(8)],
            )
            for b in range(4)
        ]

        # Rcon XOR on the 32-bit SubWord result.
        node_rcon = step.add_subcipher(
            ConstXOR_CVL(32, rcon_val, name="Rcon"),
            [(sb_nodes[b], (i, 8*b + i)) for b in range(4) for i in range(8)],
        )

        # Chain-XOR the four new key words.
        node_w0 = step.add_subcipher(
            XOR_CVL(32, name="XOR_w0"),
            [(step.IN, (i, i)) for i in range(32)]
            + [(node_rcon, (i, 32 + i)) for i in range(32)],
        )
        node_w1 = step.add_subcipher(
            XOR_CVL(32, name="XOR_w1"),
            [(step.IN, (32 + i, i)) for i in range(32)]
            + [(node_w0, (i, 32 + i)) for i in range(32)],
        )
        node_w2 = step.add_subcipher(
            XOR_CVL(32, name="XOR_w2"),
            [(step.IN, (64 + i, i)) for i in range(32)]
            + [(node_w1, (i, 32 + i)) for i in range(32)],
        )
        node_w3 = step.add_subcipher(
            XOR_CVL(32, name="XOR_w3"),
            [(step.IN, (96 + i, i)) for i in range(32)]
            + [(node_w2, (i, 32 + i)) for i in range(32)],
        )

        step.add_output(
            [(node_w0, (i, i)) for i in range(32)]
            + [(node_w1, (i, 32 + i)) for i in range(32)]
            + [(node_w2, (i, 64 + i)) for i in range(32)]
            + [(node_w3, (i, 96 + i)) for i in range(32)],
        )
        return step


class AES_CVL:
    """Implementation of the AES in CiVerLy."""

    def __init__(self, R, k=None, name=None) -> None:
        r"""
        Implement AES-128 in CiVerLy.

        By default round keys are zero, which leaves correctness of the
        data path verifiable without a key schedule.  Pass a 128-bit master
        key ``k`` to inject the real AES-128 round keys via
        :meth:`civerly.cipher.Cipher.set_master_key`.

        INPUT:

            - ``R`` -- integer; Number of rounds.

            - ``k`` -- integer (128-bit); Master key (optional).  When given,
              the AES-128 round keys are derived and injected immediately.

            - ``name`` -- string; The name of the cipher (optional).
              This will be used to name the cipher and the corresponding file
              generated (such as the reports and cipher graphs).


        EXAMPLES:

        Encrypt a message with zero round keys (to verify the data path)::

            sage: from civerly.util import vec_to_int, int_to_vec
            sage: from civerly.cipher_implementations.aes import AES_CVL
            sage: aes = AES_CVL(R=4)
            sage: hex(vec_to_int(aes(int_to_vec(0x12345678,128))))
            '0x1491385e17259a1555f377e76ade6090'

        Encrypt using the NIST FIPS 197 Appendix B test vector::

            sage: from civerly.util import vec_to_int, int_to_vec
            sage: from civerly.cipher_implementations.aes import AES_CVL
            sage: aes = AES_CVL(R=10, k=0x2b7e151628aed2a6abf7158809cf4f3c)
            sage: pt = int_to_vec(0x3243f6a8885a308d313198a2e0370734, 128)
            sage: hex(vec_to_int(aes(pt)))
            '0x3925841d02dc09fbdc118597196a0b32'

        TESTS:

            Verify test vectors::

                sage: P = 0x1234567890987654321abcdefedcba0
                sage: cs = [
                ....:     0x7c0162e0a7fd1f851a556e4ddf2617bd, # AES1(P)
                ....:     0xb6981be566842beb9bf0137c4d078c73, # AES2(P)
                ....:     0x8011ddf414a586dc3b0871e850fc4f95, # AES3(P)
                ....:     0x7c3089404453904968689a654de53516, # ...
                ....:     0xef63cdf14945417a8803975e5d8668cd,
                ....:     0x4ada4ac43340a0ffc6756bf119226362,
                ....:     0xa8a93ce499d039c14fb8ed53fc16234e,
                ....:     0x8fc22e4ef439f3060d0f2fba8d83fb93,
                ....:     0x0719a7dde361e32d0b592e786871806a,
                ....:     0xcf23445ee76d654762219a8ed3a234b8,
                ....:     0x2d03d9dc09af74816d45448d4bafa7a2,
                ....:     0xbed1717ed72429ab86584135b617f6a9 # AES12(P)
                ....: ]
                sage: all([vec_to_int(AES_CVL(R)(int_to_vec(P, 128))) == cs[R-1]
                ....:     for R in range(1, 13)])
                True

            Analyse with other solvers::

                sage: from civerly.cipher_implementations.aes import AES_CVL
                sage: from civerly.model_options import *
                sage: import tempfile
                sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - glpk
                ....:   aes = AES_CVL(R=2)
                ....:   model_options = MODEL_OPTIONS(
                ....:       cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
                ....:       optimization=OPTIMIZATION.MILP,
                ....:       granularity=GRANULARITY.WORDWISE,
                ....:       linear_layer_modeling=LINEAR_LAYER_MODELING.BRANCH_NUMBER,
                ....:       milp_solver=GLPK_CVL(),
                ....:       path=Path(tmpdir))
                ....:   aes.analyse(model_options)
                644 variables and 653 constraints were written to '...'
                5
                sage: from civerly.cipher_implementations.aes import AES_CVL
                sage: from civerly.model_options import *
                sage: import tempfile
                sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - glpk
                ....:   aes = AES_CVL(R=2)
                ....:   model_options = MODEL_OPTIONS(
                ....:       cryptanalysis=CRYPTANALYSIS.LINEAR,
                ....:       optimization=OPTIMIZATION.MILP,
                ....:       granularity=GRANULARITY.WORDWISE,
                ....:       linear_layer_modeling=LINEAR_LAYER_MODELING.GENERALIZED_WORDWISE,
                ....:       milp_solver=GLPK_CVL(),
                ....:       path=Path(tmpdir))
                ....:   aes.analyse(model_options)
                640 variables and 641 constraints were written to '...'
                5
                sage: from civerly.cipher_implementations.aes import AES_CVL
                sage: from civerly.model_options import *
                sage: import tempfile
                sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - gurobi
                ....:   aes = AES_CVL(R=10)
                ....:   model_options = MODEL_OPTIONS(
                ....:       cryptanalysis=CRYPTANALYSIS.LINEAR,
                ....:       optimization=OPTIMIZATION.MILP,
                ....:       granularity=GRANULARITY.WORDWISE,
                ....:       linear_layer_modeling=LINEAR_LAYER_MODELING.BRANCH_NUMBER,
                ....:       milp_solver=GUROBI_CVL(),
                ....:       path=Path(tmpdir))
                ....:   aes.analyse(model_options)
                3236 variables and 3437 constraints were written to '...'
                55
                sage: from civerly.cipher_implementations.aes import AES_CVL
                sage: from civerly.model_options import *
                sage: import tempfile
                sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - gurobi
                ....:   aes = AES_CVL(R=10)
                ....:   model_options = MODEL_OPTIONS(
                ....:       cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
                ....:       optimization=OPTIMIZATION.MILP,
                ....:       granularity=GRANULARITY.WORDWISE,
                ....:       linear_layer_modeling=LINEAR_LAYER_MODELING.GENERALIZED_WORDWISE,
                ....:       milp_solver=GUROBI_CVL(),
                ....:       path=Path(tmpdir))
                ....:   aes.analyse(model_options)
                3200 variables and 3329 constraints were written to '...'
                55

            Trying the parallel construction
            :math:`F(x_1, x_2) := AES(x_1) || AES(x_2)`:

                sage: from civerly.cipher_implementations.aes import AES_CVL
                sage: from civerly.model_options import *
                sage: from civerly.aeslike import AESlike
                sage: import tempfile
                sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - gurobi
                ....:   cipher = AESlike(8, 4, 8, name="parallelAES")
                ....:   node1 = cipher.add_subcipher(
                ....:       AES_CVL(R=10),
                ....:       [(cipher.IN, (i, i)) for i in range(16)])
                ....:   node2 = cipher.add_subcipher(
                ....:       AES_CVL(R=10),
                ....:       [(cipher.IN, (i + 16, i)) for i in range(16)])
                ....:   edges = [(node1, (i, i)) for i in range(16)]
                ....:   edges += [(node2, (i, i + 16)) for i in range(16)]
                ....:   cipher.add_output(edges)
                ....:   model_options = MODEL_OPTIONS(
                ....:       cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
                ....:       optimization=OPTIMIZATION.MILP,
                ....:       granularity=GRANULARITY.WORDWISE,
                ....:       linear_layer_modeling=LINEAR_LAYER_MODELING.GENERALIZED_WORDWISE,
                ....:       milp_solver=GUROBI_CVL(),
                ....:       path=Path(tmpdir))
                ....:   cipher.analyse(model_options)
                ....:   cipher.generate_report(model_options)
                ....:   trail = str(cipher.get_trail(model_options))
                ....:   assert "Unnamed Component" not in trail
                6592 variables and 6849 constraints were written to '...'
                55
                Output file in: ...

            The result shows that roughly half of the states are all-zero,
            which indicates that one of the two AES instances is completely
            passive. In turn, this is coherent with the fact that the parallel
            construction does not increase the ciphers security against
            differential cryptanalysis.
        """
        if name is None:
            name = "AES"

        # sboxlayer is an AESlike cipher, containing the sbox components
        # (SBox_CVL) 16 times in parallel.
        sboxlayer = AESlike(8, 4, 4, name="SBoxLayer")
        sb = SBox_CVL(AES_S, name="SBox")

        for i in range(16):
            node = sboxlayer.add_subcipher(sb, [(sboxlayer.IN, (i, 0))])
            sboxlayer.add_output([(node, (0, i))])

        # permutation specifying the ShiftRow operation.
        tpt = [0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3]
        shiftrow = PermuteLayer_CVL(tpt, word_coarseness=8, name="ShiftRows")

        # Generating the binary matrix describing GF(2^8) arithmetic.
        # ------------------------------------------------ #
        I = identity_matrix(GF(2), 8)  # noqa: E741

        mul2 = matrix(GF(2), [[0, 1, 0, 0, 0, 0, 0, 0],
                              [0, 0, 1, 0, 0, 0, 0, 0],
                              [0, 0, 0, 1, 0, 0, 0, 0],
                              [1, 0, 0, 0, 1, 0, 0, 0],
                              [1, 0, 0, 0, 0, 1, 0, 0],
                              [0, 0, 0, 0, 0, 0, 1, 0],
                              [1, 0, 0, 0, 0, 0, 0, 1],
                              [1, 0, 0, 0, 0, 0, 0, 0]])
        mul3 = mul2 + I
        arr = [[mul2, mul3, I, I],
               [I, mul2, mul3, I],
               [I, I, mul2, mul3],
               [mul3, I, I, mul2]]
        # ------------------------------------------------ #

        # LinearLayer_CVL accepts a binary matrix, which is sufficient to fully
        # describe its behaviour
        mixcolumn = LinearLayer_CVL(block_matrix(GF(2), arr, subdivide=False),
                                    branch_number_differential=5,
                                    branch_number_linear=5, name="MixColumn")

        # Constructing the AES round
        # ------------------------------------------------ #
        aes_round = AESlike(8, 4, 4, name="AES-round")
        edges = [(aes_round.IN, (i, i)) for i in range(16)]
        node_sboxlayer = aes_round.add_subcipher(sboxlayer, edges)
        edges = [(node_sboxlayer, (i, i)) for i in range(16)]
        node_shiftrow = aes_round.add_subcipher(shiftrow, edges)
        for j in range(4):  # MixColumn is added 4 times in parallel
            edges = [(node_shiftrow, (i + 4*j, i)) for i in range(4)]
            node_mixcolumn = aes_round.add_subcipher(mixcolumn, edges)
            edges = [(node_mixcolumn, (i, i + 4*j)) for i in range(4)]
            aes_round.add_output(edges)
        # ------------------------------------------------ #

        # Adding round functions (and the last non-full round) into the
        # aes_cipher
        # ------------------------------------------------ #
        aes_cipher = AESlike(8, 4, 4, name=name)

        node = aes_cipher.IN
        edges = [(node, (i, i)) for i in range(16)]
        node = aes_cipher.add_subcipher(RoundkeyXOR_CVL(128, 0, name="AddRoundKey"), edges)

        for r in range(R-1):
            edges = [(node, (i, i)) for i in range(16)]
            node = aes_cipher.add_subcipher(aes_round, edges)
            edges = [(node, (i, i)) for i in range(16)]
            node = aes_cipher.add_subcipher(RoundkeyXOR_CVL(128, 0, name="AddRoundKey"), edges)

        edges = [(node, (i, i)) for i in range(16)]
        node = aes_cipher.add_subcipher(sboxlayer, edges)
        edges = [(node, (i, i)) for i in range(16)]
        node = aes_cipher.add_subcipher(shiftrow, edges)
        edges = [(node, (i, i)) for i in range(16)]
        node = aes_cipher.add_subcipher(RoundkeyXOR_CVL(128, 0, name="AddRoundKey"), edges)

        aes_cipher.add_output([(node, (i, i)) for i in range(16)])
        # ------------------------------------------------ #

        aes_cipher._rk_components = [aes_cipher.nodes[2*r+1] for r in range(R)] + [aes_cipher.nodes[2*R+2]]
        aes_cipher.key_schedule = AES_KeySchedule_CVL(R)

        self.aes_cipher = aes_cipher

        if k is not None:
            aes_cipher.set_master_key(k)

    def __new__(cls, *args, **kwargs):
        """Instantiate the AES."""
        instance = super(AES_CVL, cls).__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.aes_cipher
