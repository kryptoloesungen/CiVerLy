from civerly.addrx import AddRX
from civerly.cipher_implementations.base import CipherImplementation_CVL
from civerly.component import (
    C_CVL,
    XOR_CVL,
    ModAdd_CVL,
    RotateLayer_CVL,
)

# ~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~- #
#   Building Chacha QRF in CiVerLy
# ~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~- #


class ChachaQRF_CVL(AddRX):
    def __init__(self, name="Chacha-QRF"):
        r"""
        The CiVerLy implementation of the Chacha QRF. Since there is nothing
        to tweak, it does not take any parameters (except the name). This cipher is
        "plug-and-play" usable, i.e. it can be directly used when imported.

        EXAMPLES::

            sage: from civerly.util import int_to_vec, vec_to_int
            sage: from civerly.cipher_implementations.chacha \
            ....:   import ChachaQRF_CVL
            sage: qrf = ChachaQRF_CVL()
            sage: hex(vec_to_int(qrf(int_to_vec(0x12345678, 128))))
            '0x812345677611b618b1cf660b5b5753d7'
            sage: hex(vec_to_int(qrf(int_to_vec(
            ....:   0xaeaeaea0_aeaeaea1_aeaeaea2_aeaeaea3,
            ....: 128))))
            '0x4e209e041e6d48ca64ff9a52c26df7bd'

        TESTS::

            sage: from civerly.cipher_implementations.chacha \
            ....:   import ChachaQRF_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - cryptominisat
            ....:   cipher = ChachaQRF_CVL()
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sat_solver=SOLVER.CRYPTOMINISAT,
            ....:     solve_range=(0, 8),
            ....:     path=Path(tmpdir))
            ....:   cipher.analyse(model_options=model_options)
            ....:   cipher.generate_report(model_options)
            ....:   trail = str(cipher.get_trail(model_options))
            ....:   assert "Unnamed Component" not in trail
            1916 variables and 4957 clauses were written to '...'
            0
            Output file in: ...

            sage: from civerly.cipher_implementations.chacha \
            ....:   import ChachaQRF_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - cadical
            ....:   cipher = ChachaQRF_CVL()
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sat_solver=SOLVER.CADICAL,
            ....:     solve_range=(0, 8),
            ....:     path=Path(tmpdir))
            ....:   cipher.analyse(model_options=model_options)
            ....:   cipher.generate_report(model_options)
            ....:   trail = str(cipher.get_trail(model_options))
            ....:   assert "Unnamed Component" not in trail
            1916 variables and 4957 clauses were written to '...'
            0
            Output file in: ...

            sage: from civerly.cipher_implementations.chacha \
            ....:   import ChachaQRF_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - cryptominisat
            ....:   cipher = ChachaQRF_CVL()
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.LINEAR,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sat_solver=SOLVER.CRYPTOMINISAT,
            ....:     path=Path(tmpdir))
            ....:   cipher.analyse(model_options=model_options)
            1920 variables and 5797 clauses were written to '...'
            0

        """
        super().__init__(32, 4, 4, name=name)

        add = ModAdd_CVL(32, name="add")
        rot16 = RotateLayer_CVL(32, 16, name="rot16")
        rot12 = RotateLayer_CVL(32, 12, name="rot12")
        rot8 = RotateLayer_CVL(32, 8, name="rot8")
        rot7 = RotateLayer_CVL(32, 7, name="rot7")
        xor = XOR_CVL(32, name="xor")

        # Components of QRF
        a0 = self.add_subcipher(add, [(self.IN, (0, 0)), (self.IN, (1, 1))])
        d1 = self.add_subcipher(xor, [(a0, (0, 0)), (self.IN, (3, 1))])
        d2 = self.add_subcipher(rot16, [(d1, (0, 0))])
        c3 = self.add_subcipher(add, [(self.IN, (2, 0)), (d2, (0, 1))])
        b4 = self.add_subcipher(xor, [(self.IN, (1, 0)), (c3, (0, 1))])
        b5 = self.add_subcipher(rot12, [(b4, (0, 0))])
        a6 = self.add_subcipher(add, [(a0, (0, 0)), (b5, (0, 1))])
        d7 = self.add_subcipher(xor, [(a6, (0, 0)), (d2, (0, 1))])
        d8 = self.add_subcipher(rot8, [(d7, (0, 0))])
        c9 = self.add_subcipher(add, [(d8, (0, 0)), (c3, (0, 1))])
        ba = self.add_subcipher(xor, [(c9, (0, 0)), (b5, (0, 1))])
        bb = self.add_subcipher(rot7, [(ba, (0, 0))])

        self.add_output([(a6, (0, 0)), (bb, (0, 1)), (c9, (0, 2)), (d8, (0, 3))])


class Chacha_CVL(CipherImplementation_CVL, AddRX):
    def __init__(self, R=20, key_schedule=None, key=None, name="Chacha"):
        r"""
        The CiVerLy implementation of the Chacha Cipher. It takes the
        following arguments:

            - ``R`` -- integer; Number of rounds (default 20)

            - ``key_schedule`` -- :class:`civerly.keyschedule.KeySchedule`
              (optional); Unused, since Chacha has no round key components
              (default: ``None``).

            - ``key`` -- integer (optional); Unused, since Chacha has no
              round key components (default: ``None``).

            - ``name`` -- string; The name of the cipher (default: "Chacha").
              Will be used to name the cipher and the corresponding files
              generated (such as the reports and cipher graphs).

        This cipher is "plug-and-play" usable, i.e. it can be directly
        used when imported.

        EXAMPLES::

            sage: from civerly.util import int_to_vec, vec_to_int
            sage: from civerly.cipher_implementations.chacha import Chacha_CVL
            sage: chacha = Chacha_CVL(10)
            sage: hex(vec_to_int(chacha(int_to_vec(0x12345678, 384))))
            '0x830ea31f9682b3636956bd110cc048c79cc417bfa8f4bf073478c1627a57a6636b5722956e674b993b8f0622d1a5e0ed5cc62d7a23d03d82a08cd38fb7fae35e'
            sage: chacha_cipher = Chacha_CVL(20)
            sage: hex(vec_to_int(chacha_cipher(int_to_vec(0xaeaeaea0aeaeaea1aeaeaea2aeaeaea3_aeaeaea4aeaeaea5aeaeaea6aeaeaea7_aeaeaea8aeaeaea9aeaeaeaAaeaeaeaB, 384))))
            '0x7b435b3af7b4f2ef11672cb917259cb6f218b24ca321714fe1c2dc6f628b75de65cffb65d6c83b2f029f9e0e3143f5da905e5da7e3b2643f4b07c630011873be'

        TESTS::

            sage: from civerly.cipher_implementations.chacha import Chacha_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - cryptominisat
            ....:   cipher = Chacha_CVL(1)
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sat_solver=SOLVER.CRYPTOMINISAT,
            ....:     solve_range=(0, 4),
            ....:     path=Path(tmpdir))
            ....:   cipher.analyse(model_options=model_options)
            12512 variables and 34145 clauses were written to '...'
            2



        """
        super().__init__(32, 12, 16, R=R, key_schedule=key_schedule, key=key, name=name)

        chacha_qr = ChachaQRF_CVL()

        # ~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~ #
        #   Building Chacha from the QRFs in CiVerLy
        # ~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~ #

        # ------------------------------------------------------------------- #
        # Chacha accepts a 256-bit key + 128-bit IV, which is
        # 12 words x 32 bits. It further outputs a 512-bit state,
        # which is 16 words x 32 bits.
        # ------------------------------------------------------------------- #

        # The state is kept row-major, as in the specification: word 4i + j is
        # row i, column j. ``state[w]`` is the (node, word) currently holding
        # word ``w``. Odd rounds apply the QRF to the columns
        # (j, 4 + j, 8 + j, 12 + j), even rounds to the diagonals
        # (j, 4 + (j + 1) % 4, 8 + (j + 2) % 4, 12 + (j + 3) % 4).
        constants = self.add_subcipher(
            C_CVL(128, 0x61707865_3320646E_79622D32_6B206574, name="Chacha-const"),
            [],
        )
        initial = {w: (constants, w) for w in range(4)}
        initial |= {w: (self.IN, w - 4) for w in range(4, 16)}

        state = dict(initial)
        for r in range(1, self.R + 1):
            diagonal = 1 if r % 2 == 0 else 0
            for j in range(4):
                words = [4 * i + (j + diagonal * i) % 4 for i in range(4)]
                node = self.add_subcipher(
                    chacha_qr,
                    [(state[w][0], (state[w][1], i)) for i, w in enumerate(words)],
                )
                for i, w in enumerate(words):
                    state[w] = (node, i)

        # Final addition of the initial state
        add = ModAdd_CVL(32, name="add")
        for w in range(16):
            node = self.add_subcipher(
                add,
                [
                    (initial[w][0], (initial[w][1], 0)),
                    (state[w][0], (state[w][1], 1)),
                ],
            )
            self.add_output([(node, (0, w))])
