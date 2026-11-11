r"""
The ``CipherImplementation_CVL`` base class shared by all cipher
implementations in :mod:`civerly.cipher_implementations`.

A concrete implementation inherits from ``CipherImplementation_CVL`` *and* from
the structural cipher class it is built on (e.g. :class:`civerly.cipher.Cipher`,
:class:`civerly.sboxcipher.SBoxCipher`, :class:`civerly.aeslike.AESlike`, ...),
in exactly that order. It forwards the structural arguments to
``super().__init__``, builds its graph on ``self`` and, if it supports round
keys, sets ``self._rk_components`` and injects the round keys itself::

    class PRESENT_CVL(CipherImplementation_CVL, WordSBoxCipher):
        def __init__(self, R=31, key_schedule=None, key=None, name="PRESENT"):
            super().__init__(4, 16, 16, R=R, key_schedule=key_schedule, key=key, name=name)

            ...  # add sub ciphers to ``self``, using ``self.R`` etc.

            self._rk_components = [...]
            if key_schedule is not None and key is not None:
                self.set_round_keys(key)

The instance is the cipher itself, so it can be used directly
("plug-and-play").
"""

from civerly.cipher import Cipher


class CipherImplementation_CVL(Cipher):
    def __init__(self, *args, R, key_schedule=None, key=None, name, **kwargs):
        r"""
        Initialize the structural parent class with ``args``, ``name`` and
        ``kwargs`` and store the attributes common to all cipher
        implementations.

        INPUT:

            - ``args`` -- positional arguments passed on to the structural
              parent class (e.g. ``wordsize, input_num_words,
              output_num_words`` for :class:`civerly.wordsboxcipher.WordSBoxCipher`).

            - ``R`` -- integer; Number of rounds.

            - ``key_schedule`` -- :class:`civerly.keyschedule.KeySchedule`
              (optional); Key schedule instance used to derive round keys from
              ``key`` via :meth:`civerly.cipher.Cipher.set_round_keys`.

            - ``key`` -- integer or list of integers (optional); The master
              key.

            - ``name`` -- string; The name of the cipher.

        OUTPUT: The (still empty) cipher with the additional public
        attributes ``R``, ``key_schedule`` and ``key``. Building the cipher
        graph and injecting the round keys is left to the implementation.

        TESTS::

            sage: from civerly.cipher_implementations.base \
            ....:   import CipherImplementation_CVL
            sage: from civerly.cipher_implementations.present import PRESENT_CVL
            sage: present = PRESENT_CVL(R=3)
            sage: isinstance(present, CipherImplementation_CVL)
            True
            sage: present.R, present.key_schedule, present.key, present.name
            (3, None, None, 'PRESENT')

        A new cipher implementation has to pass ``R`` and ``name`` as
        keyword arguments, next to the positional arguments of its
        structural parent class::

            sage: from civerly.wordsboxcipher import WordSBoxCipher
            sage: class Toy_CVL(CipherImplementation_CVL, WordSBoxCipher):
            ....:     def __init__(self, R=2, key_schedule=None, key=None):
            ....:         super().__init__(4, 2, 2, R=R,
            ....:             key_schedule=key_schedule, key=key, name="Toy")
            sage: toy = Toy_CVL(R=5, key=0x2a)
            sage: toy.R, toy.key_schedule, toy.key, toy.name
            (5, None, 42, 'Toy')

        Building an implementation with differently specified parameters
        fails. Omitting ``R`` and ``name``::

            sage: class Toy_CVL(CipherImplementation_CVL, WordSBoxCipher):
            ....:     def __init__(self):
            ....:         super().__init__(4, 2, 2)
            sage: Toy_CVL()
            Traceback (most recent call last):
            ...
            TypeError: CipherImplementation_CVL.__init__() missing 2 required keyword-only arguments: 'R' and 'name'

        Inheriting from the structural parent class first::

            sage: class Toy_CVL(WordSBoxCipher, CipherImplementation_CVL):
            ....:     def __init__(self, R=2):
            ....:         super().__init__(4, 2, 2, R=R, name="Toy")
            sage: Toy_CVL()
            Traceback (most recent call last):
            ...
            TypeError: WordBasedCipher.__init__() got an unexpected keyword argument 'R'

        """
        self.R = R
        self.key = key
        super().__init__(*args, name=name, **kwargs)
        self.key_schedule = key_schedule

    @classmethod
    def _init_from_dict(cls, d):
        r"""
        Construct an empty shell of the structural parent class, as the
        constructor of a cipher implementation builds the full cipher.
        """
        for base in cls.__mro__:
            if not issubclass(base, CipherImplementation_CVL):
                return base._init_from_dict(d)
