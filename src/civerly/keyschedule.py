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
    """
    pass
