from civerly.cipher import Cipher


class KeySchedule(Cipher):
    r"""
    Base class for cipher key schedules implemented as CiVerLy DAGs.

    Subclass ``KeySchedule`` and build the key expansion as a CiVerLy DAG
    using standard components (``XOR_CVL``, ``SBox_CVL``, etc.).  The
    schedule takes the master key as input and outputs all round keys
    concatenated.

    To use a key schedule, pass the master key to
    :meth:`civerly.cipher.Cipher.set_master_key`::

        sage: from civerly.cipher_implementations.aes import AES_CVL
        sage: from civerly.util import int_to_vec, vec_to_int
        sage: aes = AES_CVL(R=10, k=0x2b7e151628aed2a6abf7158809cf4f3c)
        sage: pt = int_to_vec(0x3243f6a8885a308d313198a2e0370734, 128)
        sage: hex(vec_to_int(aes(pt)))
        '0x3925841d02dc09fbdc118597196a0b32'

    The key schedule is only used for correctness testing and has no effect
    on the MILP or SAT model.

    **Implementing a subclass**

    Every subclass must override ``__call__`` with the following contract:

    - **Input:** ``k`` -- the master key as a Python integer.

    - **Output:** a list of round-key integers, one entry per round key, in
      round order (round key 0 first).  Each integer represents a single
      round key in the same bit ordering used by the cipher (MSB = index 0).

    The list length must equal the number of ``RK_CVL`` components registered
    on the cipher (i.e. ``len(cipher._rk_components)``).  When
    :meth:`civerly.cipher.Cipher.set_master_key` is called, it iterates over
    that list and writes each value into the corresponding ``RK_CVL``
    constant, so that subsequent ``cipher.eval()`` calls use the correct keys.

    The typical implementation pattern is::

        def __call__(self, k):
            from civerly.util import int_to_vec, vec_to_int
            n = self.input_length          # master-key size in bits
            rk_size = n                    # size of one round key in bits
            bits = self.eval(int_to_vec(k, n))
            return [vec_to_int(bits[i*rk_size:(i+1)*rk_size])
                    for i in range(self.output_length // rk_size)]

    Note that this ``__call__`` signature (integer in, list of integers out)
    intentionally differs from the inherited ``Cipher.__call__`` (bit-vector
    in, bit-vector out) and must be overridden in every ``KeySchedule``
    subclass.
    """
    pass
