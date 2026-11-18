from civerly.andrx import AndRX
from civerly.cipher_implementations.base import CipherImplementation_CVL
from civerly.component import AND_CVL, XOR_CVL, RotateLayer_CVL, RoundkeyXOR_CVL
from civerly.keyschedule import KeySchedule

# Round: Add round constant -> theta(key, state) -> pi1 -> gamma -> pi2
# theta: linear diffusion + key injection (XORs + byte-rotations)
# pi1, pi2: word rotations (RX part)
# gamma: the nonlinear layer (this is where AND + NOT appear)

# round constant rc1
rc1 = [
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
]  # fmt: skip
RC_FINAL = 0xD4


class NOEKEON_KeySchedule_CVL(KeySchedule):
    def __init__(self, R=16, name="Noekeon-KeySchedule"):
        r"""
        Noekeon key schedule (direct-key mode) as a CiVerLy DAG.

        In direct-key mode, Noekeon uses the 128-bit master key, split into
        the four 32-bit words ``K0, K1, K2, K3`` (``K0`` most significant), as
        working key unchanged in every theta. The DAG is therefore pure
        output wiring: the master key is repeated once per round, plus once
        more for the final theta of the full 16-round cipher.

        INPUT:

            - ``R`` -- integer; Number of rounds, same meaning as ``R`` of
              :class:`NOEKEON_CVL` (default: 16)

            - ``name`` -- string; The name of the key schedule
              (default: "Noekeon-KeySchedule")

        OUTPUT: :meth:`eval` returns ``4 * R`` 32-bit round keys (``4 * R +
        4`` for ``R == 16``), ordered ``K0, K1, K2, K3`` per theta in round
        order, matching ``NOEKEON_CVL._rk_components``.

        EXAMPLES::

            sage: from civerly.cipher_implementations.noekeon import (
            ....:   NOEKEON_KeySchedule_CVL)
            sage: ks = NOEKEON_KeySchedule_CVL(R=2)
            sage: [hex(rk) for rk in ks(0x000102030405060708090a0b0c0d0e0f)]
            ['0x10203', '0x4050607', '0x8090a0b', '0xc0d0e0f',
             '0x10203', '0x4050607', '0x8090a0b', '0xc0d0e0f']
            sage: len(NOEKEON_KeySchedule_CVL()(0x0))
            68

        End-to-end encryption via ``set_round_keys``::

            sage: from civerly.cipher_implementations.noekeon import NOEKEON_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: noekeon = NOEKEON_CVL(key_schedule=NOEKEON_KeySchedule_CVL())
            sage: noekeon.set_round_keys(0xb1656851699e29fa24b70148503d2dfc)
            sage: P = 0x2a78421b87c7d0924f26113f1d1349b2
            sage: hex(vec_to_int(noekeon(int_to_vec(P, 128))))
            '0xe2f687e07b75660ffc372233bc47532c'
        """
        assert 0 <= R <= 16
        self._num_thetas = R + (1 if R == 16 else 0)
        super().__init__(128, 128 * self._num_thetas, name=name)
        self._R = R
        self.add_output(
            [
                (self.IN, (i, t * 128 + i))
                for t in range(self._num_thetas)
                for i in range(128)
            ]
        )

    def eval(self, k):
        r"""
        Expand master key ``k`` into the list of 32-bit round keys
        ``[K0, K1, K2, K3] * (number of thetas)``.

        INPUT:

            - ``k`` -- integer; 128-bit master key.

        OUTPUT: List of ``4 * R`` integers (``4 * R + 4`` for ``R == 16``).
        """
        from civerly.cipher import Cipher
        from civerly.util import int_to_vec, vec_to_int

        bits = Cipher.eval(self, int_to_vec(k, self.input_length))
        return [
            vec_to_int(bits[i * 32 : (i + 1) * 32])
            for i in range(self.output_length // 32)
        ]


class NOEKEON_CVL(CipherImplementation_CVL, AndRX):
    def __init__(self, R=16, key_schedule=None, key=None, name="Noekeon"):
        r"""
        CiVerLy implementation of Noekeon (https://gro.noekeon.org/Noekeon-spec.pdf).
        It takes the following arguments:

            - ``R`` -- integer; Number of rounds (default: 16)

            - ``key_schedule`` -- :class:`civerly.keyschedule.KeySchedule`
              (optional); Key schedule instance used to derive round keys from
              ``key`` via ``set_round_keys``. Pass a
              :class:`NOEKEON_KeySchedule_CVL` instance (with the same ``R``)
              to use the Noekeon direct-key schedule (the master key words
              ``K0..K3`` in every theta), a custom ``KeySchedule`` subclass
              instance, or :class:`civerly.keyschedule.DefaultKeySchedule_CVL`
              to pass explicit round keys (``4 * R`` 32-bit words, ``4 * R +
              4`` for ``R == 16``, ordered ``K0, K1, K2, K3`` per theta).
              Defaults to ``None`` (no key schedule, all-zero round keys).

            - ``key`` -- integer or list of integers (optional); The master
              key passed to ``key_schedule``, immediately expanded and
              injected via ``set_round_keys`` when both are given. Has no
              effect when ``key_schedule`` is ``None``. When using
              :class:`civerly.keyschedule.DefaultKeySchedule_CVL`, this is the
              list of round keys (round key 0 first).

            - ``name`` -- string; The name of the cipher (default: "Noekeon").
              This will be used to name the cipher and the corresponding file
              generated (such as the reports and cipher graphs).

        EXAMPLES::

            sage: from civerly.cipher_implementations.noekeon import NOEKEON_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: cipher = NOEKEON_CVL()
            sage: hex(vec_to_int(cipher(int_to_vec(0x04000e01000000f00a020000030c0d0, 128))))
            '0x759c49db3dea7e6896ba0a56575df255'

        TESTS::
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: from civerly.cipher_implementations.noekeon import (
            ....:   NOEKEON_CVL, NOEKEON_KeySchedule_CVL)
            sage: P = 0x00000000000000000000000000000000
            sage: K = 0x00000000000000000000000000000000
            sage: C = 0xb1656851699e29fa24b70148503d2dfc
            sage: cipher = NOEKEON_CVL(key=K, key_schedule=NOEKEON_KeySchedule_CVL())
            sage: vec_to_int(cipher(int_to_vec(P, 128))) == C
            True

            sage: from civerly.util import int_to_vec, vec_to_int
            sage: from civerly.cipher_implementations.noekeon import (
            ....:   NOEKEON_CVL, NOEKEON_KeySchedule_CVL)
            sage: K = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
            sage: P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
            sage: C = 0x2a78421b87c7d0924f26113f1d1349b2
            sage: cipher = NOEKEON_CVL(key=K, key_schedule=NOEKEON_KeySchedule_CVL())
            sage: vec_to_int(cipher(int_to_vec(P, 128))) == C
            True

            sage: from civerly.util import int_to_vec, vec_to_int
            sage: from civerly.cipher_implementations.noekeon import (
            ....:   NOEKEON_CVL, NOEKEON_KeySchedule_CVL)
            sage: K = 0xb1656851699e29fa24b70148503d2dfc
            sage: P = 0x2a78421b87c7d0924f26113f1d1349b2
            sage: C = 0xe2f687e07b75660ffc372233bc47532c
            sage: cipher = NOEKEON_CVL(key=K, key_schedule=NOEKEON_KeySchedule_CVL())
            sage: vec_to_int(cipher(int_to_vec(P, 128))) == C
            True

        Without a key schedule, ``key`` has no effect (all-zero round keys)::

            sage: cipher = NOEKEON_CVL(key=K)
            sage: vec_to_int(cipher(int_to_vec(P, 128))) == C
            False
            sage: vec_to_int(cipher(int_to_vec(P, 128))) == \
            ....:   vec_to_int(NOEKEON_CVL()(int_to_vec(P, 128)))
            True

        Explicit round keys via
        :class:`civerly.keyschedule.DefaultKeySchedule_CVL` (here the
        direct-key words of ``K``, repeated for all 17 thetas)::

            sage: from civerly.keyschedule import DefaultKeySchedule_CVL
            sage: rks = [(K >> (96 - 32 * i)) & 0xFFFFFFFF for i in range(4)] * 17
            sage: cipher = NOEKEON_CVL(
            ....:   key=rks, key_schedule=DefaultKeySchedule_CVL(32, 68))
            sage: vec_to_int(cipher(int_to_vec(P, 128))) == C
            True

        Models for differential cryptanalysis::

            sage: # optional - cryptominisat # optional - espresso
            sage: from civerly.cipher_implementations.noekeon import NOEKEON_CVL
            sage: cipher = NOEKEON_CVL(R=1)
            sage: from civerly.model_options import *
            sage: from pathlib import Path
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
            8096 variables and 16897 clauses were written to ...
            16

            sage: # optional - cadical # optional - espresso
            sage: from civerly.cipher_implementations.noekeon import NOEKEON_CVL
            sage: cipher = NOEKEON_CVL(R=1)
            sage: from civerly.model_options import *
            sage: from pathlib import Path
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
            8096 variables and 16897 clauses were written to ...
            16


        Models for linear cryptanalysis::

            sage: # optional - cryptominisat # optional - espresso
            sage: from civerly.cipher_implementations.noekeon import NOEKEON_CVL
            sage: cipher = NOEKEON_CVL(R=1)
            sage: from civerly.model_options import *
            sage: from pathlib import Path
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
            8096 variables and 17345 clauses were written to ...
            10

            sage: # optional - cadical # optional - espresso
            sage: from civerly.cipher_implementations.noekeon import NOEKEON_CVL
            sage: cipher = NOEKEON_CVL(R=1)
            sage: from civerly.model_options import *
            sage: from pathlib import Path
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
            8096 variables and 17345 clauses were written to ...
            10

        """
        super().__init__(32, 4, 4, R=R, key_schedule=key_schedule, key=key, name=name)

        assert 0 <= self.R <= 16
        # xor operation
        xor = XOR_CVL(32, name="xor")
        # AND operation
        and1 = AND_CVL(32, name="and")
        # key addition
        not1 = RoundkeyXOR_CVL(32, 0xFFFFFFFF, name="not")
        # rotation operation
        rotL8 = RotateLayer_CVL(32, 8, name="rotl8")
        rotL24 = RotateLayer_CVL(32, 24, name="rotl24")
        # subkeys addition (working key words K0..K3); the actual values are
        # injected via ``set_round_keys`` (all zero without a key schedule)
        kx0 = RoundkeyXOR_CVL(32, 0x0, name="k0")
        kx1 = RoundkeyXOR_CVL(32, 0x0, name="k1")
        kx2 = RoundkeyXOR_CVL(32, 0x0, name="k2")
        kx3 = RoundkeyXOR_CVL(32, 0x0, name="k3")

        # THETA
        theta = AndRX(32, 4, 4, name="theta")
        # temp = a0 ^ a2
        t0 = theta.add_subcipher(xor, [(theta.IN, (0, 0)), (theta.IN, (2, 1))])
        # temp ^= ROTL8(temp) ^ ROTL24(temp)
        t0_r8 = theta.add_subcipher(rotL8, [(t0, (0, 0))])
        t0_r24 = theta.add_subcipher(rotL24, [(t0, (0, 0))])
        t1 = theta.add_subcipher(xor, [(t0, (0, 0)), (t0_r8, (0, 1))])
        t2 = theta.add_subcipher(xor, [(t1, (0, 0)), (t0_r24, (0, 1))])
        # a1 ^= t2
        a1 = theta.add_subcipher(xor, [(theta.IN, (1, 0)), (t2, (0, 1))])
        # a3 ^= t2
        a3 = theta.add_subcipher(xor, [(theta.IN, (3, 0)), (t2, (0, 1))])
        # key add
        a0k = theta.add_subcipher(kx0, [(theta.IN, (0, 0))])
        a1k = theta.add_subcipher(kx1, [(a1, (0, 0))])
        a2k = theta.add_subcipher(kx2, [(theta.IN, (2, 0))])
        a3k = theta.add_subcipher(kx3, [(a3, (0, 0))])
        # temp = a1k ^ a3k
        u0 = theta.add_subcipher(xor, [(a1k, (0, 0)), (a3k, (0, 1))])
        # temp ^= ROTL8(temp) ^ ROTL24(temp)
        u0_r8 = theta.add_subcipher(rotL8, [(u0, (0, 0))])
        u0_r24 = theta.add_subcipher(rotL24, [(u0, (0, 0))])
        u1 = theta.add_subcipher(xor, [(u0, (0, 0)), (u0_r8, (0, 1))])
        u2 = theta.add_subcipher(xor, [(u1, (0, 0)), (u0_r24, (0, 1))])
        # a0 ^= u2
        a0 = theta.add_subcipher(xor, [(a0k, (0, 0)), (u2, (0, 1))])
        # a2 ^= u2
        a2 = theta.add_subcipher(xor, [(a2k, (0, 0)), (u2, (0, 1))])

        theta.add_output([(a0, (0, 0)), (a1k, (0, 1)), (a2, (0, 2)), (a3k, (0, 3))])

        pi1 = AndRX(32, 4, 4, name="pi1")
        rot1 = RotateLayer_CVL(32, 1, name="rotl1")
        rot5 = RotateLayer_CVL(32, 5, name="rotl5")
        rot2 = RotateLayer_CVL(32, 2, name="rotl2")

        p1_a1 = pi1.add_subcipher(rot1, [(pi1.IN, (1, 0))])
        p1_a2 = pi1.add_subcipher(rot5, [(pi1.IN, (2, 0))])
        p1_a3 = pi1.add_subcipher(rot2, [(pi1.IN, (3, 0))])

        pi1.add_output(
            [
                (pi1.IN, (0, 0)),
                (p1_a1, (0, 1)),
                (p1_a2, (0, 2)),
                (p1_a3, (0, 3)),
            ]
        )

        pi2 = AndRX(32, 4, 4, name="pi2")
        rot31 = RotateLayer_CVL(32, 31, name="rotr1")
        rot27 = RotateLayer_CVL(32, 27, name="rotr5")
        rot30 = RotateLayer_CVL(32, 30, name="rotr2")

        p2_a1 = pi2.add_subcipher(rot31, [(pi2.IN, (1, 0))])
        p2_a2 = pi2.add_subcipher(rot27, [(pi2.IN, (2, 0))])
        p2_a3 = pi2.add_subcipher(rot30, [(pi2.IN, (3, 0))])

        pi2.add_output(
            [
                (pi2.IN, (0, 0)),
                (p2_a1, (0, 1)),
                (p2_a2, (0, 2)),
                (p2_a3, (0, 3)),
            ]
        )

        # GAMMA
        gamma = AndRX(32, 4, 4, name="gamma")
        # t = ~(a3|a2) = (~a3) & (~a2)
        na3_1 = gamma.add_subcipher(not1, [(gamma.IN, (3, 0))])
        na2_1 = gamma.add_subcipher(not1, [(gamma.IN, (2, 0))])
        t_or1 = gamma.add_subcipher(and1, [(na3_1, (0, 0)), (na2_1, (0, 1))])
        a1_1 = gamma.add_subcipher(xor, [(gamma.IN, (1, 0)), (t_or1, (0, 1))])
        # a0 ^= a2 & a1
        a2_and_a1_1 = gamma.add_subcipher(and1, [(gamma.IN, (2, 0)), (a1_1, (0, 1))])
        a0_1 = gamma.add_subcipher(xor, [(gamma.IN, (0, 0)), (a2_and_a1_1, (0, 1))])
        # After swap: a0 = old a3, a3 = a0_1, a1 = a1_1, a2 = old a2
        x01 = gamma.add_subcipher(xor, [(gamma.IN, (3, 0)), (a1_1, (0, 1))])
        x012 = gamma.add_subcipher(xor, [(x01, (0, 0)), (a0_1, (0, 1))])
        a2_1 = gamma.add_subcipher(xor, [(gamma.IN, (2, 0)), (x012, (0, 1))])
        # second time: a1 ^= ~(a3 | a2) with updated a3=a0_1 and a2=a2_1
        na3_2 = gamma.add_subcipher(not1, [(a0_1, (0, 0))])  # ~a3
        na2_2 = gamma.add_subcipher(not1, [(a2_1, (0, 0))])  # ~a2
        t_or2 = gamma.add_subcipher(and1, [(na3_2, (0, 0)), (na2_2, (0, 1))])
        a1_2 = gamma.add_subcipher(xor, [(a1_1, (0, 0)), (t_or2, (0, 1))])
        # a0 ^= a2 & a1
        a2_and_a1_2 = gamma.add_subcipher(and1, [(a2_1, (0, 0)), (a1_2, (0, 1))])
        a0_2 = gamma.add_subcipher(xor, [(gamma.IN, (3, 0)), (a2_and_a1_2, (0, 1))])
        gamma.add_output(
            [
                (a0_2, (0, 0)),
                (a1_2, (0, 1)),
                (a2_1, (0, 2)),
                (a0_1, (0, 3)),
            ]
        )

        round_cipher = AndRX(32, 4, 4, name="noekeon_round")
        rc_xor = RoundkeyXOR_CVL(32, 0x0, name="rc")  # const set per round
        node_rc = round_cipher.add_subcipher(rc_xor, [(round_cipher.IN, (0, 0))])
        node_theta = round_cipher.add_subcipher(
            theta,
            [
                (node_rc, (0, 0)),
                (round_cipher.IN, (1, 1)),
                (round_cipher.IN, (2, 2)),
                (round_cipher.IN, (3, 3)),
            ],
        )
        node_pi1 = round_cipher.add_subcipher(
            pi1, [(node_theta, (i, i)) for i in range(4)]
        )
        node_gamma = round_cipher.add_subcipher(
            gamma, [(node_pi1, (i, i)) for i in range(4)]
        )
        node_pi2 = round_cipher.add_subcipher(
            pi2, [(node_gamma, (i, i)) for i in range(4)]
        )
        round_cipher.add_output([(node_pi2, (i, i)) for i in range(4)])
        self._round_template = round_cipher
        self._node_rc = node_rc

        node = self.IN
        round_nodes = []
        for r in range(self.R):
            rc_word = int(rc1[r]) & 0xFF
            round_cipher.nodes[node_rc].const = rc_word
            node = self.add_subcipher(round_cipher, [(node, (i, i)) for i in range(4)])
            round_nodes.append(node)

        # finalization: a0 ^= (RC_FINAL<<24), then theta(key,state)
        final_node = node
        if self.R == 16:
            rc_final_xor = RoundkeyXOR_CVL(32, int(RC_FINAL) & 0xFF, name="rc_final")
            node_rcf = self.add_subcipher(rc_final_xor, [(node, (0, 0))])
            final_node = self.add_subcipher(
                theta,
                [(node_rcf, (0, 0)), (node, (1, 1)), (node, (2, 2)), (node, (3, 3))],
            )

        self.add_output([(final_node, (i, i)) for i in range(4)])

        # Collect references to the key-word additions K0..K3 inside theta,
        # one set per round (in round order), followed by the set inside the
        # final theta (only present for R == 16). ``not1`` is a fixed
        # constant (bitwise NOT) and is not key material.
        key_nodes = [a0k, a1k, a2k, a3k]
        self._rk_components = [
            self.nodes[rn].nodes[node_theta].nodes[kn]
            for rn in round_nodes
            for kn in key_nodes
        ]
        if self.R == 16:
            self._rk_components += [
                self.nodes[final_node].nodes[kn] for kn in key_nodes
            ]

        if key_schedule is not None and key is not None:
            self.set_round_keys(key)
