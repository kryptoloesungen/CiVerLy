from civerly.cipher import Cipher
from civerly.component import ModAdd_CVL, RotateLayer_CVL


# cipher using ModAdd_CVL, enforcing probabilistic transition
class Toy6(Cipher):
    def __init__(self):
        r"""

        TESTS::

            sage: # optional - cryptominisat
            sage: from civerly.cipher_implementations.toy_ciphers.toy6 \
            ....:   import Toy6
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   cipher = Toy6()
            ....:   model_options = MODEL_OPTIONS(
            ....:       cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:       optimization=OPTIMIZATION.SAT,
            ....:       granularity=GRANULARITY.BITWISE,
            ....:       sat_solver=SOLVER.CRYPTOMINISAT,
            ....:       path=Path(tmpdir))
            ....:   cipher.analyse(model_options)
            ....:   cipher.generate_report(model_options)
            ....:   trail = str(cipher.get_trail(model_options))
            ....:   assert "Unnamed Component" not in trail
            397 variables and 1142 clauses were written to '...'
            2
            Output file in: ...


        """
        super().__init__(32, 16, name="Toy6")

        rot5 = RotateLayer_CVL(16, r=5, name="rot5")
        rot7 = RotateLayer_CVL(16, r=7, name="rot7")
        modadd = ModAdd_CVL(16, name="ModAdd")

        node_rot1 = self.add_subcipher(rot5, [(self.IN, (i, i)) for i in range(16)])
        node_rot2 = self.add_subcipher(
            rot7, [(self.IN, (i + 16, i)) for i in range(16)]
        )

        node_xor1 = self.add_subcipher(
            modadd,
            [(node_rot1, (i, i)) for i in range(16)]
            + [(self.IN, (i, i + 16)) for i in range(16)],
        )
        node_xor2 = self.add_subcipher(
            modadd,
            [(node_rot2, (i, i)) for i in range(16)]
            + [(self.IN, (i + 16, i + 16)) for i in range(16)],
        )

        node_modadd1 = self.add_subcipher(
            modadd,
            [(node_xor1, (i, i)) for i in range(16)]
            + [(node_xor2, (i, i + 16)) for i in range(16)],
        )
        self.add_output([(node_modadd1, (i, i)) for i in range(16)])
