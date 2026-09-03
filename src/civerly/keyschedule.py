from abc import abstractmethod

from civerly.cipher import Cipher


class KeySchedule(Cipher):
    r"""
    Base class for cipher key schedules implemented as CiVerLy DAGs.

    Subclass ``KeySchedule``, build the key expansion as a CiVerLy DAG in
    ``__init__``, and implement :meth:`eval` to convert a master key integer
    into the list of round-key integers.

    To use a key schedule, pass an instance of it to a cipher implementation's
    ``key_schedule`` argument, together with the master key::

        sage: from civerly.cipher_implementations.aes import (
        ....:   AES_CVL, AES_KeySchedule_CVL)
        sage: from civerly.util import int_to_vec, vec_to_int
        sage: aes = AES_CVL(
        ....:   R=10, k=0x2b7e151628aed2a6abf7158809cf4f3c,
        ....:   key_schedule=AES_KeySchedule_CVL(10))
        sage: pt = int_to_vec(0x3243f6a8885a308d313198a2e0370734, 128)
        sage: hex(vec_to_int(aes(pt)))
        '0x3925841d02dc09fbdc118597196a0b32'
        sage: aes = AES_CVL(
        ....:   R=10, k=0x2b7e151628aed2a6abf7158809cf4f3c,
        ....:   key_schedule=None)
        sage: pt = int_to_vec(0x3243f6a8885a308d313198a2e0370734, 128)
        sage: hex(vec_to_int(aes(pt)))
        '0x663fabe27c3acc01248d244350519f89'

    The key schedule is only used for correctness testing and has no effect
    on the MILP or SAT model.

    **Implementing a subclass**

    Every subclass must implement :meth:`eval`:

    - **Input:** ``master_key`` -- the master key as a Python integer.

    - **Output:** a list of round-key integers, one entry per round key, in
      round order (round key 0 first).  Each integer represents a single
      round key in the same bit ordering used by the cipher (MSB = index 0).

    The list length must equal the number of ``RK_CVL`` components registered
    on the cipher (i.e. ``len(cipher._rk_components)``).  When
    :meth:`civerly.cipher.Cipher.set_round_keys` is called, it iterates over
    that list and writes each value into the corresponding ``RK_CVL``
    constant, so that subsequent ``cipher.eval()`` calls use the correct keys.

    The typical implementation pattern is::

        def eval(self, master_key):
            from civerly.util import int_to_vec, vec_to_int
            n = self.input_length          # master-key size in bits
            rk_size = n                    # size of one round key in bits
            bits = Cipher.eval(self, int_to_vec(master_key, n))
            return [vec_to_int(bits[i*rk_size:(i+1)*rk_size])
                    for i in range(self.output_length // rk_size)]

    Note that ``Cipher.eval`` must be called explicitly here because
    ``KeySchedule.eval`` overrides it with a different signature (integer in,
    list of integers out).
    """

    def __call__(self, master_key):
        r"""
        See :meth:`eval`.
        """
        return self.eval(master_key)

    @abstractmethod
    def eval(self, master_key):
        r"""
        Expand ``master_key`` into a list of round-key integers.

        INPUT:

            - ``master_key`` -- integer; the master key.

        OUTPUT: list of integers, one per round key, in round order.
        """


class DefaultKeySchedule_CVL(KeySchedule):
    r"""
    Trivial key schedule used by cipher implementations that have no real key
    schedule implemented. It performs no expansion at all: the "master key"
    passed to it is simply the round keys concatenated MSB-first, and
    :meth:`eval` splits it back apart.

    This makes it possible to pass explicit round keys to any cipher
    implementation, in a way that is consistent with the ``key_schedule``/``k``
    interface used everywhere else, without requiring a cipher-specific
    ``KeySchedule`` subclass.

    INPUT:

        - ``rk_width`` -- integer; the number of bits in a single round key.

        - ``rk_count`` -- integer; the number of round keys.

        - ``name`` -- string (optional); the name of the key schedule.

    EXAMPLES::

        sage: from civerly.keyschedule import DefaultKeySchedule_CVL
        sage: ks = DefaultKeySchedule_CVL(16, 2)
        sage: ks(0x00010002)
        [1, 2]

    Pass an instance together with ``k`` to any cipher implementation to
    inject explicit round keys::

        sage: from civerly.cipher_implementations.gift import GIFT64_CVL
        sage: rks = [0x1111111111111111, 0x2222222222222222]
        sage: k = (rks[0] << 64) | rks[1]
        sage: gift64 = GIFT64_CVL(R=2, k=k, key_schedule=DefaultKeySchedule_CVL(64, 2))
        sage: gift64.key_schedule(k) == rks
        True
    """

    def __init__(self, rk_width, rk_count, name="DefaultKeySchedule"):
        super().__init__(rk_width * rk_count, rk_width * rk_count, name=name)
        self._rk_width = rk_width
        self._rk_count = rk_count

    def eval(self, master_key):
        r"""
        Split ``master_key`` into ``self._rk_count`` round keys of
        ``self._rk_width`` bits each (MSB-first).

        INPUT:

            - ``master_key`` -- integer; the round keys concatenated
              MSB-first.

        OUTPUT: list of ``self._rk_count`` integers, in round order.
        """
        mask = (1 << self._rk_width) - 1
        return [
            (master_key >> (self._rk_width * (self._rk_count - 1 - i))) & mask
            for i in range(self._rk_count)
        ]
