from civerly.andrx import AndRX
from civerly.component import AND_CVL, XOR_CVL, RotateLayer_CVL, RoundkeyXOR_CVL


class SIMECK_CVL:
    def __init__(
        self,
        block_size=32,
        key_size=64,
        R=32,
        key_schedule=None,
        rks=None,
        name="Simeck",
    ):
        r"""
        CiVerLy implementation of the Simeck cipher. It takes the following arguments:

            - ``block_size`` -- integer; The block size (default: 32).

            - ``key_size`` -- integer; The key size (default: 64).

            - ``key_schedule`` -- :class:`civerly.keyschedule.KeySchedule`
              (optional); Key schedule instance used by ``set_round_keys`` to
              derive round keys from a master key. No built-in key schedule is
              implemented for Simeck; pass a custom ``KeySchedule`` subclass
              instance. Defaults to ``None`` (no key schedule).

            - ``rks`` -- list[int]; Round keys (default: []).

            - ``R`` -- integer; Number of rounds (default: 32)

            - ``name`` -- string; The name of the cipher (default: "Simeck").
              Will be used to name the cipher and the corresponding files
              generated (such as the reports and cipher graphs).


        EXAMPLES::
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: from civerly.cipher_implementations.simeck import SIMECK_CVL
            sage: simeck_cipher = SIMECK_CVL()
            sage: hex(vec_to_int(simeck_cipher(int_to_vec(0xabcd1234, 32))))
            '0x193970'

        TESTS::
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: from civerly.cipher_implementations.simeck import SIMECK_CVL
            sage: P = 0x65656877
            sage: rks = [
            ....:   0x0100, 0x0908, 0x1110, 0x1918, 0xeded, 0xd4d5, 0xdddd,
            ....:   0x9093, 0x2b2b, 0x090b, 0x1314, 0x1818, 0xc7c1, 0xd2de,
            ....:   0xdcd8, 0xa866, 0xcf5b, 0x0c8a, 0x7bad, 0x0275, 0x29b3,
            ....:   0x7580, 0x829b, 0x8ece, 0x0d4f, 0x8d5b, 0xe83b, 0x62ed,
            ....:   0x6155, 0xa2e8, 0x92b1, 0x7fbe
            ....:   ]
            sage: C = 0x770d2c76
            sage: simeck_cipher = SIMECK_CVL(rks=rks)
            sage: vec_to_int(simeck_cipher(int_to_vec(P, 32))) == C
            True

        Models for differential cryptanalysis::

            sage: # optional - cryptominisat # optional - espresso
            sage: from civerly.cipher_implementations.simeck import SIMECK_CVL
            sage: cipher = SIMECK_CVL(R=8)
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     sat_solver=SOLVER.CRYPTOMINISAT,
            ....:     solve_range=(16, 20),
            ....:     logic_minimizer=SOLVER.ESPRESSO,
            ....:     path=Path(tmpdir))
            ....:   cipher.analyse(model_options=model_options)
            3904 variables and 8129 clauses were written to ...
            18

            sage: # optional - cadical # optional - espresso
            sage: from civerly.cipher_implementations.simeck import SIMECK_CVL
            sage: cipher = SIMECK_CVL(R=8)
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     sat_solver=SOLVER.CADICAL,
            ....:     solve_range=(16, 20),
            ....:     logic_minimizer=SOLVER.ESPRESSO,
            ....:     path=Path(tmpdir))
            ....:   cipher.analyse(model_options=model_options)
            3904 variables and 8129 clauses were written to ...
            18

        Models for linear cryptanalysis::

            sage: # optional - cryptominisat # optional - espresso
            sage: from civerly.cipher_implementations.simeck import SIMECK_CVL
            sage: cipher = SIMECK_CVL(R=11)
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.LINEAR,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     sat_solver=SOLVER.CRYPTOMINISAT,
            ....:     solve_range=(10, 20),
            ....:     logic_minimizer=SOLVER.ESPRESSO,
            ....:     path=Path(tmpdir))
            ....:   cipher.analyse(model_options=model_options)
            5296 variables and 12465 clauses were written to ...
            13

            sage: # optional - cadical # optional - espresso
            sage: from civerly.cipher_implementations.simeck import SIMECK_CVL
            sage: cipher = SIMECK_CVL(R=11)
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.LINEAR,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     sat_solver=SOLVER.CADICAL,
            ....:     solve_range=(10, 20),
            ....:     logic_minimizer=SOLVER.ESPRESSO,
            ....:     path=Path(tmpdir))
            ....:   cipher.analyse(model_options=model_options)
            5296 variables and 12465 clauses were written to ...
            13

        Remove files::
            sage: import shutil
            sage: shutil.rmtree("./DOCTEST-Simeck-Models/", ignore_errors=True)
        """

        if rks is None:
            rks = []
        assert (block_size, key_size) == (32, 64), (
            "As of now, only Simeck32/64 is supported"
        )

        if rks == []:
            rks = [0 for _ in range(R)]

        simeck_round = AndRX(16, 2, 2, name="simeck_round")
        # rotate operations
        rot1 = RotateLayer_CVL(16, 1, name="rotate1")
        rot5 = RotateLayer_CVL(16, 5, name="rotate5")
        # AND operation
        and1 = AND_CVL(16, name="and")
        # xor operation
        xor1 = XOR_CVL(16, name="xor")
        # key addition
        key_add = RoundkeyXOR_CVL(16, 0x0, name="rk")

        # Implementation of SIMECK round function
        # L_{i+1} = R_i
        # R_{i+1} = [(L_i ^ (R_i & ROL(R_i, 5))) ^ ROL(R_i, 1)] ^ k_i

        # ROL(R, 1)
        node_rot1 = simeck_round.add_subcipher(rot1, [(simeck_round.IN, (0, 0))])
        # ROL(R, 5)
        node_rot5 = simeck_round.add_subcipher(rot5, [(simeck_round.IN, (0, 0))])
        # R & ROL(R, 5)
        node_and1 = simeck_round.add_subcipher(
            and1, [(simeck_round.IN, (0, 0)), (node_rot5, (0, 1))]
        )
        # (R & ROL(R, 5)) ^ ROL1
        node_xor1 = simeck_round.add_subcipher(
            xor1, [(node_and1, (0, 0)), (node_rot1, (0, 1))]
        )
        # ((R & ROL(R, 5)) ^ ROL1) ^ L
        node_xor2 = simeck_round.add_subcipher(
            xor1, [(node_xor1, (0, 0)), (simeck_round.IN, (1, 1))]
        )
        # R_{i+1}
        node_keyxor = simeck_round.add_subcipher(key_add, [(node_xor2, (0, 0))])
        simeck_round.add_output([(node_keyxor, (0, 0)), (simeck_round.IN, (0, 1))])

        # apply the feistel round function 32 times, each round using a different round key
        simeck_cipher = AndRX(16, 2, 2, name=name)
        node = simeck_cipher.IN
        for r in range(R):
            simeck_round.nodes[node_keyxor].const = rks[r]
            node = simeck_cipher.add_subcipher(
                simeck_round, [(node, (0, 0)), (node, (1, 1))]
            )

        simeck_cipher.add_output([(node, (0, 0)), (node, (1, 1))])
        simeck_cipher.key_schedule = key_schedule
        self.simeck_cipher = simeck_cipher

    def __new__(cls, *args, **kwargs):
        instance = super().__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.simeck_cipher
