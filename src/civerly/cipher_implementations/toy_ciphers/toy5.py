from civerly.cipher_implementations.toy_ciphers.toy3 import Toy3
from civerly.cipher_implementations.toy_ciphers.toy4 import Toy4
from civerly.sboxcipher import SBoxCipher


# cipher using cascade of toy3 and toy4
class Toy5(SBoxCipher):
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
            ....:       sat_solver=SOLVER.CADICAL,
            ....:       logic_minimizer=SOLVER.ESPRESSO,
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
            ....:       sat_solver=SOLVER.CADICAL,
            ....:       logic_minimizer=SOLVER.ESPRESSO,
            ....:       path=Path(tmpdir))
            ....:   cipher.analyse(model_options)
            ....:   cipher.generate_report(model_options)
            ....:   trail = str(cipher.get_trail(model_options))
            ....:   assert "Unnamed Component" not in trail
            2940 variables and 13997 clauses were written to '...'
            8
            Output file in: ...
            Using existing file ..., make sure it is up to date!
            3256 variables and 11381 clauses were written to '...'
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
            ....:       milp_solver=SOLVER.SCIP,
            ....:       path=Path(tmpdir))
            ....:   cipher.analyse(model_options)
            ....:   cipher.generate_report(model_options)
            ....:   trail = str(cipher.get_trail(model_options))
            ....:   assert "Unnamed Component" not in trail
            3404 variables and 4177 constraints were written to '...'
            8
            Output file in: ...

        """
        super().__init__(48, 16, name="Toy5")

        toy3 = Toy3()
        toy4 = Toy4()

        node1 = self.add_subcipher(toy3, [(self.IN, (i, 31 - i)) for i in range(32)])
        node2 = self.add_subcipher(
            toy3, [(self.IN, (i + 16, 31 - i)) for i in range(32)]
        )
        node3 = self.add_subcipher(
            toy4,
            [(node1, (i, i)) for i in range(16)]
            + [(node2, (i, i + 16)) for i in range(16)],
        )
        node4 = self.add_subcipher(
            toy4,
            [(node1, (i + 16, i)) for i in range(16)]
            + [(node2, (i + 16, i + 16)) for i in range(16)],
        )
        node5 = self.add_subcipher(
            toy4,
            [(node3, (i, (3 * i) % 16)) for i in range(16)]
            + [(self.IN, (i + 32, ((5 * i) % 16) + 16)) for i in range(16)],
        )

        node = self.add_subcipher(
            toy4,
            [(node4, (i, (i + 3) % 16)) for i in range(16)]
            + [(node5, (i, i + 16)) for i in range(16)],
        )

        self.add_output([(node, (i, i)) for i in range(16)])
