"""
Rudimentary implementation of the GIFT block cipher.

We only implement the S-box and the linear layer. This is already enough to
analyze GIFT with CiVerLy.
"""
from civerly.wordsboxcipher import WordSBoxCipher
from civerly.component import SBox_CVL, PermuteLayer_CVL
from sage.crypto.sboxes import GIFT as gift_S


class GIFT_CVL:
    """Rudimentary implementation of GIFT."""

    def __init__(self, R=28, name=None):
        r"""
        Initialise GIFT.

        TESTS::

        Model the cipher with MILP:

            sage: from civerly.cipher_implementations.gift import GIFT_CVL
            sage: from civerly.model_options import *
            sage: from pathlib import Path
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - scip
            ....:   gift_cipher = GIFT_CVL(R=2)
            ....:   model_options = MODEL_OPTIONS(
            ....:       cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:       optimization=OPTIMIZATION.MILP,
            ....:       granularity=GRANULARITY.BITWISE,
            ....:       sbox_modeling=SBOX_MODELING.CONVEX_HULL,
            ....:       milp_solver=SOLVER.SCIP,
            ....:       path=Path(tmpdir)
            ....:   )
            ....:   gift_cipher.analyse(model_options)
            2560 variables and 2849 constraints were written to '...'
            3.4150374993

            sage: from civerly.cipher_implementations.gift import GIFT_CVL
            sage: from civerly.model_options import *
            sage: from pathlib import Path
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - scip  # optional - espresso
            ....:   gift_cipher = GIFT_CVL(R=2)
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.MILP,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     milp_solver=SOLVER.SCIP,
            ....:     logic_minimizer=SOLVER.ESPRESSO,
            ....:     path=Path(tmpdir)
            ....:   )
            ....:   gift_cipher.analyse(model_options) 
            2560 variables and 4161 constraints were written to '...'
            3.4150374993
            
            sage: from civerly.cipher_implementations.gift import GIFT_CVL
            sage: from civerly.model_options import *
            sage: from pathlib import Path
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - scip
            ....:   gift_cipher = GIFT_CVL(R=2)
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.MILP,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.DISTORTED_BALL,
            ....:     milp_solver=SOLVER.SCIP,
            ....:     path=Path(tmpdir)
            ....:   )
            ....:   gift_cipher.analyse(model_options) 
            2560 variables and 3585 constraints were written to '...'
            3.4150374993

        Model the cipher with SAT using different values for ``sat_precision``:

            sage: from civerly.cipher_implementations.gift import GIFT_CVL
            sage: from civerly.model_options import *
            sage: from pathlib import Path
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - cryptominisat  # optional - espresso
            ....:   gift_cipher = GIFT_CVL(R=2)
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.EXCLUDE_ODD,
            ....:     sat_solver=SOLVER.CRYPTOMINISAT,
            ....:     logic_minimizer=SOLVER.ESPRESSO,
            ....:     path=Path(tmpdir)
            ....:   )
            ....:   gift_cipher.analyse(model_options)
            2560 variables and 6401 clauses were written to '...'
            3

            sage: from civerly.cipher_implementations.gift import GIFT_CVL
            sage: from civerly.model_options import *
            sage: from pathlib import Path
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - cryptominisat  # optional - espresso
            ....:   gift_cipher = GIFT_CVL(R=2)
            ....:   model_options = MODEL_OPTIONS(
            ....:       cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.EXCLUDE_ODD,
            ....:     solve_range=(0, 10),
            ....:     sat_precision=1,
            ....:     sat_solver=SOLVER.CRYPTOMINISAT,
            ....:     logic_minimizer=SOLVER.ESPRESSO,
            ....:     path=Path(tmpdir)
            ....:   )
            ....:   gift_cipher.analyse(model_options)
            2560 variables and 6401 clauses were written to '...'
            3.4

        Simulate external Espresso minimization::

            sage: from civerly.cipher_implementations.gift import GIFT_CVL
            sage: from civerly.model_options import *
            sage: from pathlib import Path
            sage: import os
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - cryptominisat  # optional - espresso
            ....:   gift_cipher = GIFT_CVL(R=2)
            ....:   model_options = MODEL_OPTIONS(
            ....:       cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.EXCLUDE_ODD,
            ....:     solve_range=(0, 10),
            ....:     sat_precision=1,
            ....:     sat_solver=SOLVER.CRYPTOMINISAT,
            ....:     logic_minimizer=None,
            ....:     path=Path(tmpdir)
            ....:   )
            ....:   gift_cipher.analyse(model_options)
            ....:   _ = os.popen("espresso -epos "
            ....:   f"{tmpdir}/espresso-d1bda7a_in.pla > "
            ....:   f"{tmpdir}/espresso-d1bda7a_out.pla").read()
            ....:   gift_cipher.analyse(model_options)
            Optimization problem for Espresso has been written to...
            Using existing file ..., make sure it is up to date!
            2560 variables and 6401 clauses were written to '...'
            3.4

        """
        if name is None:
            name = "GIFT"

        s = SBox_CVL(gift_S, name="S")

        # sboxlayer is an SBoxCipher containing the sbox components (SBox_CVL)
        # 16 times in parallel.
        sboxlayer = WordSBoxCipher(4, 16, 16, name="SBoxLayer")
        for j in range(16):
            node = sboxlayer.add_subcipher(s, [(sboxlayer.IN, (j, 0))])
            sboxlayer.add_output([(node, (0, j))])

        # GIFT permutation layer
        permutation = PermuteLayer_CVL(
            [
                0, 17, 34, 51, 48, 1, 18, 35, 32, 49, 2, 19, 16, 33, 50, 3,
                4, 21, 38, 55, 52, 5, 22, 39, 36, 53, 6, 23, 20, 37, 54, 7,
                8, 25, 42, 59, 56, 9, 26, 43, 40, 57, 10, 27, 24, 41, 58, 11,
                12, 29, 46, 63, 60, 13, 30, 47, 44, 61, 14, 31, 28, 45, 62, 15,
            ],
            name="Permutation"
        )

        # Implementation of the GIFT round.
        # ------------------------------------------------ #
        gift_round = WordSBoxCipher(4, 16, 16, name="gift_round")
        edges = [(gift_round.IN, (i, i)) for i in range(16)]
        node = gift_round.add_subcipher(sboxlayer, edges)
        edges = [(node, (i, i)) for i in range(16)]
        node = gift_round.add_subcipher(permutation, edges)
        gift_round.add_output([(node, (i, i)) for i in range(16)])
        # ------------------------------------------------ #

        # Implementation of the GIFT cipher.
        # ------------------------------------------------ #
        gift_cipher = WordSBoxCipher(4, 16, 16, name=name)
        cipher_node = gift_cipher.IN
        for r in range(R):
            edges = [(cipher_node, (i, i)) for i in range(16)]
            cipher_node = gift_cipher.add_subcipher(gift_round, edges)

        gift_cipher.add_output([(cipher_node, (i, i)) for i in range(16)])
        # ------------------------------------------------ #

        self.gift_cipher = gift_cipher

    def __new__(cls, *args, **kwargs):
        """Instantiate a GIFT cipher."""
        instance = super(GIFT_CVL, cls).__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.gift_cipher
