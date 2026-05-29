r"""
The ``WordBasedCipher`` class, a subclass of ``Cipher`` allowing only
specific operations.

The ``WordBasedCipher`` class inherits most of its functionality from
``Cipher``, with the restriction that there has to be a fixed ``wordsize``,
i.e. each sub-cipher must have an ``input_length`` and ``output_length``
that is a multiple of ``wordsize``.

This class is the base for the subclass ``WordSBoxCipher``,
which supports wordwise MILP-modeling, which would be impossible without
a fixed ``wordsize``. Another purpose of this class is that
``.add_subcipher()`` of ``WordBasedCipher`` and its subclasses accepts
**wordwise** edges instead of bitwise edges. However this is just a
convenience, and internally, there is no difference in the functionality.


EXAMPLES::

    sage: from civerly.cipher import Cipher
    sage: from civerly.wordbasedcipher import WordBasedCipher
    sage: from civerly.component import SBox_CVL
    sage: from sage.crypto.sboxes import AES
    sage: wbc = WordBasedCipher(8, 16, 16, name="WBC")
    sage: s8 = SBox_CVL(AES)
    sage: node_s8 = wbc.add_subcipher(s8, [(wbc.IN, (1, 0))])
    sage: cipher = Cipher(128, 128, name="Cipher")
    sage: node_s8 = cipher.add_subcipher(
    ....:   s8, [(cipher.IN, (i + 8, i)) for i in range(8)])
    sage: cipher == wbc
    True

"""

from civerly.cipher import Cipher
from civerly.component import Component


class WordBasedCipher(Cipher):

    def __init__(self, wordsize, input_num_words, output_num_words, name=None):
        r"""
        .. SEEALSO::
            - ``Cipher.__init__`` for the initialization details.

        TESTS::

            sage: from civerly.wordbasedcipher import WordBasedCipher
            sage: cipher = WordBasedCipher(8, 2, 3, name="wordbasedcipher")
            sage: cipher
            wordbasedcipher: 16 -> 24 bits
                Sub ciphers:

        """
        self.__wordsize = wordsize
        self._wrd = wordsize
        super().__init__(
            input_num_words * wordsize,
            output_num_words * wordsize,
            name
        )

    @property
    def wordsize(self):
        r"""
        A ``WordBasedCipher`` has a new attribute, which will be distributed
        onto its sub-ciphers (of either type ``WordBasedCipher`` and
        ``Component``) when added.

        sage: from civerly.wordbasedcipher import WordBasedCipher
        sage: cipher = WordBasedCipher(17, 9, 5, name="wordbasedcipher")
        sage: cipher.wordsize
        17

        """
        assert self.__wordsize > 0
        return int(self.__wordsize)

    def _to_dict(self):
        d = super()._to_dict()
        d["type"] = "WordBasedCipher"
        d["wordsize"] = self.wordsize
        return d

    @classmethod
    def _init_from_dict(cls, d):
        """
        Used in :meth:`self.load` in order to build this object from the loaded `.json` file.

        TESTS::

        Loading with any appropriate subclass of the cipher class of the exported
        cipher restores it:

            sage: from civerly.cipher_implementations.speck import SPECK_CVL
            sage: from civerly.wordbasedcipher import WordBasedCipher
            sage: from civerly.addrx import AddRX
            sage: cipher = SPECK_CVL(128, 128)
            sage: tmp = tempfile.mkdtemp()
            sage: export_file = Path(tmp) / f"{cipher.name}.json"
            sage: cipher.export(export_file)
            Object 'speck' has been exported to ...
            sage: loaded1 = WordBasedCipher.load(export_file)
            sage: sorted(cipher.__dict__) == sorted(loaded1.__dict__)
            True
            sage: loaded2 = AddRX.load(export_file)
            sage: sorted(cipher.__dict__) == sorted(loaded2.__dict__)
            True
            sage: import shutil
            sage: shutil.rmtree(tmp)

        However, if we try to load a cipher which is not a subclass of WordBasedCipher, 
        the method fails:

            sage: from civerly.cipher_implementations.toy_ciphers.toy4 import Toy4
            sage: from civerly.wordbasedcipher import WordBasedCipher
            sage: cipher = Toy4()
            sage: tmp = tempfile.mkdtemp()
            sage: export_file = Path(tmp) / f"{cipher.name}.json"
            sage: cipher.export(export_file)
            Object 'Toy4' has been exported to ...
            sage: try: 
            ....:   loaded1 = WordBasedCipher.load(export_file)
            ....: except TypeError as e:
            ....:   print(e)
            The json dictionary does not contain the attribute 'wordsize', ...
            sage: import shutil
            sage: shutil.rmtree(tmp)

        
        """
        if "wordsize" not in d.keys(): 
            raise TypeError(
                "The json dictionary does not contain the attribute 'wordsize', "
                "meaning that the exported cipher was not a subclass of WordBasedCipher."
            )
        ws = d["wordsize"]
        return cls(ws, d["input_length"] // ws, d["output_length"] // ws, name=d["name"])

    def add_subcipher(self, sub_cipher, edges):
        r"""
        The edges are now reduced. Instead of ``wordsize`` many edges going
        from a single node into another node, the convention is now that one
        edge of size ``wordsize`` goes into the respective node.
        Consequently, when inserting a ``Component`` into a
        ``WordBasedCipher``, it receives a new attribute ``self.wordsize``.

        EXAMPLES::

            sage: from civerly.cipher import Cipher
            sage: from civerly.wordbasedcipher import WordBasedCipher
            sage: from civerly.component import SBox_CVL
            sage: from sage.crypto.sboxes import AES as AES_S
            sage: wbc = WordBasedCipher(8, 16, 16, name="WordBasedCipher")
            sage: s8 = SBox_CVL(AES_S)
            sage: node_s8 = wbc.add_subcipher(s8, [(wbc.IN, (1, 0))])
            sage: cipher = Cipher(128, 128, name="Cipher")
            sage: node_s8 = cipher.add_subcipher(
            ....:   s8, [(cipher.IN, (i + 8, i)) for i in range(8)])
            sage: cipher == wbc
            True
            sage: wbc.wordsize
            8
            sage: cipher.wordsize
            Traceback (most recent call last):
            [...]
            AttributeError: 'Cipher' object has no attribute 'wordsize'

        .. SEEALSO::
            - ``Cipher.add_subcipher``
        """
        if isinstance(sub_cipher, Component):
            sub_cipher.wordsize = self.wordsize
            return super().add_subcipher(sub_cipher=sub_cipher, edges=[
                (a, (x*self.wordsize + o, y*self.wordsize + o))
                for o in range(self.wordsize) for a, (x, y) in edges
            ])
        if isinstance(sub_cipher, WordBasedCipher):
            if sub_cipher.wordsize != self.wordsize:
                raise AssertionError(f"Wordsize mismatch: {sub_cipher.wordsize = } != {self.wordsize = }") # noqa
            return super().add_subcipher(sub_cipher=sub_cipher, edges=[
                (a, (x*self.wordsize + o, y*self.wordsize + o))
                for o in range(self.wordsize) for a, (x, y) in edges
            ])
        raise TypeError(f"Trying to add illegal component {type(sub_cipher)}.")

    def add_output(self, edges):
        r"""
        Similarily to :meth:`add_subcipher`, the output edges are now reduced
        as well. Instead of ``wordsize`` many output edges coming from a node,
        the convention is now that output one edge of size ``wordsize`` is
        connected to the output.

        TESTS::

            sage: from civerly.wordbasedcipher import WordBasedCipher
            sage: cipher = WordBasedCipher(7, 4, 4, name="wordbasedcipher")
            sage: cipher.add_output([(cipher.IN, (i, i)) for i in range(4)])
            sage: cipher
            wordbasedcipher: 28 -> 28 bits
                Sub ciphers:
            sage: cipher.is_valid
            True

        """
        return super().add_output(edges=[
            (a, (x*self.wordsize + o, y*self.wordsize + o))
            for o in range(self.wordsize) for (a, (x, y)) in edges
        ])
