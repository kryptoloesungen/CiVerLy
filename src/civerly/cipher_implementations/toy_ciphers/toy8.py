from civerly.cipher import Cipher
from civerly.component import C_CVL, ModAdd_CVL, PermuteLayer_CVL


# cipher used to cover that the report generation of C_CVL works correctly
class Toy8(Cipher):
    def __init__(self):
        r"""

        TESTS::

        The test code for SAT:

            sage: # optional - cryptominisat
            sage: from civerly.cipher_implementations.toy_ciphers.toy8 \
            ....:   import Toy8
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   cipher = Toy8()
            ....:   model_options = MODEL_OPTIONS(
            ....:       cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:       optimization=OPTIMIZATION.SAT,
            ....:       granularity=GRANULARITY.BITWISE,
            ....:       sat_solver=SOLVER.CRYPTOMINISAT,
            ....:       path=Path(tmpdir))
            ....:   cipher.analyse(model_options=model_options)
            ....:   cipher.generate_report(model_options)
            ....:   trail = str(cipher.get_trail(model_options))
            ....:   assert "Unnamed Component" not in trail
            ...
            Output file in: ...

        """
        super().__init__(32, 32, name="Toy8")

        modadd = ModAdd_CVL(32, name="ModAdd")

        p = [
            31, 30, 28, 29, 27, 24, 25, 26, 23, 22, 21,
            20, 11, 12, 13, 14, 15, 16, 17, 18, 19, 10,
            5,  3,  4,  1,  0,  2,  6,  8,  9,  7,
        ]  # fmt: skip

        perm = PermuteLayer_CVL(p, name="permute")
        const = C_CVL(32, 0xDEADBEEF, name="Const")

        node = self.add_subcipher(perm, [(self.IN, (i, i)) for i in range(32)])
        node_c = self.add_subcipher(const, [])
        node = self.add_subcipher(
            modadd,
            [(node, (i, i)) for i in range(32)]
            + [(node_c, (i, i + 32)) for i in range(32)],
        )

        self.add_output([(node, (i, i)) for i in range(32)])
