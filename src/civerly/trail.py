from sage.modules.free_module_element import vector
from sage.rings.finite_rings.finite_field_constructor import GF
from civerly.util import vec_to_int


class TrailNode:
    # def __init__(self, input_length, output_length, name=None) -> None:
    def __init__(self, cipher_instance) -> None:
        self.children = []
        self.right = None
        self.input = None
        self.output = None
        self.cipher_instance = cipher_instance
        self.name = cipher_instance.name
        self.input_length = cipher_instance.input_length
        self.output_length = cipher_instance.output_length

    def _to_hex(self) -> str:
        string = ""
        if self.output is not None:
            string += f"{vec_to_int(
                vector(GF(2), self.input)
            ):0{self.input_length//4}x}"
        else:
            string += "None"
        string += " -> "
        if self.output is not None:
            string += f"{vec_to_int(
                vector(GF(2), self.output)
            ):0{self.output_length//4}x}"
        else:
            string += "None"
        return string

    def __repr__(self, _depth=-1) -> str:
        from civerly.cipher import Cipher
        string = ""
        if _depth >= 0:
            string += "\t"*_depth + "-> " + f"{self.name} : {self._to_hex()} "
        for child in self.children:
            if not isinstance(
                child.cipher_instance, Cipher._Cipher__Special_Node
            ):
                string += "\n" + child.__repr__(_depth+1)
        return string

    def verify_correctness(self):
        r"""
        Performs a coherence check of the report. It takes each of the
        intermediate states and checks whether the inputs and outputs match.
        For that, we build up a tree-like data structure where each displayed
        layer in the report is represented by a node in the tree.
        Each node in that tree has the following keys:

        - ``children`` -- list of nodes; The children nodes of ``node``
        - ``right`` -- node; the right sibling-node
        - ``val`` -- list; the values stored in that node.

        As an example, we assume the report to contain the following values in
        the states of the ExampleRound cipher (on a wordwise level, for
        simplicity). We label these states with (i) for integers i.

        ExampleRound:

            [1, 0, 0, 0, 0, 0, 0, 1] (1)
                --LinearLayer-->
            [1, 0, 0, 0, 0, 1, 0, 0] (2)
                ---SBoxLayer--->
            [1, 0, 0, 0, 0, 1, 0, 0] (3)

        LinearLayer:

            [1, 0, 0, 0, 0, 0, 0, 1] (4)
                --LinearLayer-->
            [1, 0, 0, 0, 0, 1, 0, 0] (5)

        SBoxLayer:
            [1, 0, 0, 0, 0, 1, 0, 0] (6)
                ---SBoxLayer--->
            [1, 0, 0, 0, 0, 1, 0, 0] (7)

        Now, it should hold that (1) == (4), (2) == (5), (2) == (6),
        (3) == (7), just by the fact that these layers are directly connected
        to each other (if not the same). This is exactly what this method
        checks for, for any arbitrary cipher.

        Note that this is a purely syntatic verification of the report, there
        is no validation on a semantic level! As an example, it is not
        guaranteed that (6) == (7), even though it is clear that SBoxes can
        not change the wordwise activity pattern in any way.

        """

        valid = True

        if self.children == [] or None in (self.input, self.output):
            return valid
        first_child = self.children[0]
        last_child = self.children[-1]

        bool1 = self.input == first_child.output
        if self.right is not None:
            bool2 = self.output == last_child.output
        else:
            bool2 = True

        if bool1 and bool2:
            pass  # everything is fine
        else:  # incoherent report!
            valid = False
            msg = "Report is not coherent"
            if not bool1:
                msg += f" between {self.name} and {first_child.name} (1):"
                msg += f" (self = {self._to_hex()}) | "
                msg += f"(child[0] = {first_child._to_hex()})."
            elif not bool2:
                msg += f" between {self.name} and {last_child.name} (2):"
                msg += f" (self = {self._to_hex()}) | "
                msg += f"(child[-1] = {last_child._to_hex()})."

            raise AssertionError(msg)

        for child in self.children:
            valid &= child.verify_correctness()
        return valid
