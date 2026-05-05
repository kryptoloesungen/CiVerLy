"""
A rudimentary implementation of a weakend version of PRESENT.

The S-box is swapped out such that its linearity is 12 and its differential
uniformity is 6. The main purpose of this is to test CiVerLy on trails with
non-integer weight.
"""
from civerly.wordsboxcipher import WordSBoxCipher
from civerly.component import SBox_CVL, PermuteLayer_CVL
from sage.crypto.sbox import SBox


class WEAK_PRESENT_CVL:
    """Rudimentary implementation of WEAK_PRESENT."""

    def __init__(self, R=31, name=None):
        r"""
        Initizalise WEAK_PRESENT.

        TESTS::

        Model the cipher with MILP:

            sage: from civerly.cipher_implementations.weak_present \
            ....:     import WEAK_PRESENT_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - gurobi  # optional - espresso
            ....:   weak_cipher = WEAK_PRESENT_CVL(R=2)
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.MILP,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     milp_solver=GUROBI_CVL(),
            ....:     logic_minimizer=ESPRESSO_CVL(),
            ....:     path=Path(tmpdir)
            ....:   )
            ....:   weak_cipher.analyse(model_options)
            2560 variables and 4417 constraints were written to '...'
            3.4150374993

        Use SCIP solver::

            sage: from civerly.cipher_implementations.weak_present \
            ....:     import WEAK_PRESENT_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - scip  # optional - espresso
            ....:   weak_cipher = WEAK_PRESENT_CVL(R=2)
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.MILP,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     milp_solver=SCIP_CVL(),
            ....:     logic_minimizer=ESPRESSO_CVL(),
            ....:     path=Path(tmpdir)
            ....:   )
            ....:   weak_cipher.analyse(model_options)
            2560 variables and 4417 constraints were written to '...'
            3.4150374993

        Now for linear cryptanalysis the cipher with MILP:

            sage: from civerly.cipher_implementations.weak_present \
            ....:     import WEAK_PRESENT_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - gurobi  # optional - espresso
            ....:   weak_cipher = WEAK_PRESENT_CVL(R=2)
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.LINEAR,
            ....:     optimization=OPTIMIZATION.MILP,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     milp_solver=GUROBI_CVL(),
            ....:     logic_minimizer=ESPRESSO_CVL(),
            ....:     path=Path(tmpdir)
            ....:   )
            ....:   weak_cipher.analyse(model_options)
            2560 variables and 4321 constraints were written to '...'
            1.2451124979

        Below we generate a custom model by adding constraints.
        First analyse the cipher as per usual:
            
            sage: # optional - scip, espresso
            sage: from civerly.cipher_implementations.weak_present \
            ....:   import WEAK_PRESENT_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory(delete=False) as tmpdir: 
            ....:   cipher = WEAK_PRESENT_CVL(R=3)
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.MILP,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.MORE_DUMMIES,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     milp_solver=SCIP_CVL(),
            ....:     logic_minimizer=ESPRESSO_CVL(),
            ....:     path=Path(tmpdir))
            sage: cipher.analyse(model_options)
            3648 variables and 6465 constraints were written to ...
            5.4150374993
        
        Set all input bits to active and analyse again:

            sage: # optional - scip, espresso
            sage: import builtins
            sage: model_options.overwrite = False
            sage: for i in range(cipher.input_length):
            ....:     cipher.milp.add_constraint(cipher.nodes[0].MILP_OUT[i] == 1)
            sage: cipher.analyse(model_options)
            Using existing MILP model, make sure it is up to date!
            3648 variables and 6529 constraints were written to ...
            61.8300749986
            sage: cipher.results[0]['in'] == [1]*64
            True
            
        Now overwrite the old model:
            
            sage: # optional - scip, espresso
            sage: model_options.overwrite = True
            sage: cipher.analyse(model_options)
            Using existing file ..., make sure it is up to date!
            3648 variables and 6465 constraints were written to ...
            5.4150374993
            
        Remove temporary files:

            sage: # optional - scip, espresso
            sage: import shutil
            sage: shutil.rmtree(tmpdir)

        
        """
        if name is None:
            name = "WEAK_PRESENT"

        S = SBox([7, 9, 11, 6, 2, 3, 1, 12, 4, 5, 15, 13, 8, 10, 14, 0])
        S = SBox_CVL(S, name="S")

        # sboxlayer is an SBoxCipher containing the sbox components (SBox_CVL)
        # 16 times in parallel.
        sboxlayer = WordSBoxCipher(4, 16, 16, name="SBoxLayer")
        for j in range(16):
            node = sboxlayer.add_subcipher(S, [(sboxlayer.IN, (j, 0))])
            sboxlayer.add_output([(node, (0, j))])

        # WEAK_PRESENT permutation layer
        permutation = PermuteLayer_CVL(
            [
                0, 16, 32, 48, 1, 17, 33, 49, 2, 18, 34, 50, 3, 19, 35, 51,
                4, 20, 36, 52, 5, 21, 37, 53, 6, 22, 38, 54, 7, 23, 39, 55,
                8, 24, 40, 56, 9, 25, 41, 57, 10, 26, 42, 58, 11, 27, 43, 59,
                12, 28, 44, 60, 13, 29, 45, 61, 14, 30, 46, 62, 15, 31, 47, 63
            ],
            name="Permutation"
        )

        # Implementation of the WEAK_PRESENT round.
        # ------------------------------------------------ #
        weak_round = WordSBoxCipher(4, 16, 16, name="weak_round")
        edges = [(weak_round.IN, (i, i)) for i in range(16)]
        node = weak_round.add_subcipher(sboxlayer, edges)
        edges = [(node, (i, i)) for i in range(16)]
        node = weak_round.add_subcipher(permutation, edges)
        weak_round.add_output([(node, (i, i)) for i in range(16)])
        # ------------------------------------------------ #

        # Implementation of the WEAK_PRESENT cipher.
        # ------------------------------------------------ #
        weak_cipher = WordSBoxCipher(4, 16, 16, name=name)
        cipher_node = weak_cipher.IN
        for _ in range(R):
            edges = [(cipher_node, (i, i)) for i in range(16)]
            cipher_node = weak_cipher.add_subcipher(weak_round, edges)

        weak_cipher.add_output([(cipher_node, (i, i)) for i in range(16)])
        # ------------------------------------------------ #

        self.weak_cipher = weak_cipher

    def __new__(cls, *args, **kwargs):
        """Instantiate a WEAK_PRESENT cipher."""
        instance = super(WEAK_PRESENT_CVL, cls).__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.weak_cipher
