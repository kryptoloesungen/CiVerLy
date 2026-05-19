from civerly.sboxcipher import SBoxCipher
from civerly.cipher_implementations.toy_ciphers.toy3 import Toy3
from civerly.cipher_implementations.toy_ciphers.toy4 import Toy4


# cipher using cascade of toy3 and toy4
class Toy5:
    def __init__(self):
        r"""

        TESTS::

            sage: # optional - cadical # optional - espresso
            sage: from civerly.cipher_implementations.toy_ciphers.toy5 \
            ....:   import Toy5
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   cipher = Toy5()
            ....:   model_options = MODEL_OPTIONS(
            ....:       cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:       optimization=OPTIMIZATION.SAT,
            ....:       granularity=GRANULARITY.BITWISE,
            ....:       linear_layer_modeling=LINEAR_LAYER_MODELING.EXCLUDE_ODD,
            ....:       sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:       sat_solver=CADICAL_CVL(),
            ....:       logic_minimizer=ESPRESSO_CVL(),
            ....:       path=Path(tmpdir))
            ....:   cipher.analyse(model_options)
            ....:   cipher.generate_report(model_options)
            ....:   trail = str(cipher.get_trail(model_options))
            ....:   assert "Unnamed Component" not in trail
            ....:   cipher = Toy5()
            ....:   model_options = MODEL_OPTIONS(
            ....:       cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:       optimization=OPTIMIZATION.SAT,
            ....:       granularity=GRANULARITY.BITWISE,
            ....:       linear_layer_modeling=LINEAR_LAYER_MODELING.MORE_DUMMIES,
            ....:       sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:       sat_solver=CADICAL_CVL(),
            ....:       logic_minimizer=ESPRESSO_CVL(),
            ....:       path=Path(tmpdir))
            ....:   cipher.analyse(model_options)
            ....:   cipher.generate_report(model_options)
            ....:   trail = str(cipher.get_trail(model_options))
            ....:   assert "Unnamed Component" not in trail
            2940 variables and 13997 clauses were written to '...'
            [  0 ,100] (trying w =  50) : SAT
            [  0 , 50] (trying w =  25) : SAT
            [  0 , 25] (trying w =  12) : SAT
            [  0 , 12] (trying w =   6) : UNSAT
            [  7 , 12] (trying w =   9) : SAT
            [  7 ,  9] (trying w =   8) : SAT
            [  7 ,  8] (trying w =   7) : UNSAT
            8
            Output file in: ...
            Using existing file ..., make sure it is up to date!
            3256 variables and 11381 clauses were written to '...'
            [  0 ,100] (trying w =  50) : SAT
            [  0 , 50] (trying w =  25) : SAT
            [  0 , 25] (trying w =  12) : SAT
            [  0 , 12] (trying w =   6) : UNSAT
            [  7 , 12] (trying w =   9) : SAT
            [  7 ,  9] (trying w =   8) : SAT
            [  7 ,  8] (trying w =   7) : UNSAT
            8
            Output file in: ...

            sage: # optional - scip
            sage: from civerly.cipher_implementations.toy_ciphers.toy5 \
            ....:   import Toy5
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   cipher = Toy5()
            ....:   model_options = MODEL_OPTIONS(
            ....:       cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:       optimization=OPTIMIZATION.MILP,
            ....:       granularity=GRANULARITY.BITWISE,
            ....:       linear_layer_modeling=LINEAR_LAYER_MODELING.MORE_DUMMIES,
            ....:       sbox_modeling=SBOX_MODELING.CONVEX_HULL,
            ....:       milp_solver=SCIP_CVL(),
            ....:       path=Path(tmpdir))
            ....:   cipher.analyse(model_options)
            ....:   cipher.generate_report(model_options)
            ....:   trail = str(cipher.get_trail(model_options))
            ....:   assert "Unnamed Component" not in trail
            3404 variables and 4177 constraints were written to '...'
            8
            Output file in: ...

        """
        cipher = SBoxCipher(48, 16, name="Toy5")

        toy3 = Toy3()
        toy4 = Toy4()

        node1 = cipher.add_subcipher(
            toy3, [(cipher.IN, (i, 31 - i)) for i in range(32)]
        )
        node2 = cipher.add_subcipher(
            toy3, [(cipher.IN, (i + 16, 31 - i)) for i in range(32)]
        )
        node3 = cipher.add_subcipher(
            toy4,
            [(node1, (i, i)) for i in range(16)] +
            [(node2, (i, i + 16)) for i in range(16)]
        )
        node4 = cipher.add_subcipher(
            toy4,
            [(node1, (i + 16, i)) for i in range(16)] +
            [(node2, (i + 16, i + 16)) for i in range(16)]
        )
        node5 = cipher.add_subcipher(
            toy4,
            [(node3, (i, (3*i) % 16)) for i in range(16)] +
            [(cipher.IN, (i + 32, ((5*i) % 16) + 16)) for i in range(16)]
        )

        node = cipher.add_subcipher(
            toy4,
            [(node4, (i, (i + 3) % 16)) for i in range(16)] +
            [(node5, (i, i + 16)) for i in range(16)]
        )

        cipher.add_output([(node, (i, i)) for i in range(16)])

        self.cipher = cipher

    def __new__(cls, *args, **kwargs):
        instance = super(Toy5, cls).__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.cipher
