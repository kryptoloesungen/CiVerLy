from sage.modules.free_module_element import vector
from sage.rings.finite_rings.finite_field_constructor import GF
from civerly.util import vec_to_int

import json
from civerly.component import Component
from civerly.model_options import OPTIMIZATION, GRANULARITY
from civerly.util import _between_brackets

class TrailNode:
    def __init__(self, cipher_instance, model_options, results) -> None:
        self.children : list[TrailNode] = []
        self.right = None
        self.input = None
        self.output = None
        self.cipher_instance = cipher_instance
        self.name = cipher_instance.name
        self.input_length = cipher_instance.input_length
        self.output_length = cipher_instance.output_length

        if model_options.optimization == OPTIMIZATION.MILP:
            if not hasattr(self.cipher_instance, 'dictionaries_milp'):
                with open(model_options.path / (self.cipher_instance.name + "_d.json")) as f:
                    dictionaries = json.load(f)
            else:
                dictionaries = self.cipher_instance.dictionaries_milp

        elif model_options.optimization == OPTIMIZATION.SAT:
            if not hasattr(self.cipher_instance, 'dictionaries_sat'):
                with open(model_options.path / (self.cipher_instance.name + "_d.json")) as f:
                    dictionaries = json.load(f)
            else:
                dictionaries = self.cipher_instance.dictionaries_sat

            def check_condition(comp_num, s):
                return s > self.cipher_instance.input_length + self.cipher_instance.output_length and \
                    s in dictionaries[comp_num].keys()

        depths = self.cipher_instance._dfs_traversal()

        ################################################
        nodes = self.cipher_instance.nodes
        max_width_in = max([
            sum(
                nodes[w].input_length
                for w in range(len(nodes))
                if depths[w] == depth
            )
            for depth in range(max(depths)+1)
        ])
        max_width_out = max([
            sum(
                nodes[w].output_length
                for w in range(len(nodes))
                if depths[w] == depth
            )
            for depth in range(max(depths)+1)
        ])

        if model_options.granularity == GRANULARITY.WORDWISE:
            divide_by = self.cipher_instance.wordsize
        elif model_options.granularity == GRANULARITY.BITWISE:
            divide_by = 1

        bits_in = [
            [None for _ in range(max_width_in // divide_by)]
            for _ in range(max(depths)+1)
        ]
        bits_out = [
            [None for _ in range(max_width_out // divide_by)]
            for _ in range(max(depths)+1)
        ]

        # Sort the (messy and unordered) variable values correctly
        if model_options.optimization == OPTIMIZATION.MILP:
            for var_name, var_dict in results.items():
                if var_name in ("IN", "OUT"):
                    # if var_name is MILP_IN or MILP_OUT, we skip it
                    continue
                comp_num = int(var_name[1:])
                for s_ind, solution_bit_value in var_dict.items():
                    translated_component = dictionaries[comp_num][
                        f"{var_name}[{s_ind}]"
                    ]
                    # Draw the input nodes of each component
                    bool1 = "IN" in translated_component
                    # We also draw the output of the last component.
                    bool2 = "OUT" in translated_component

                    if bool1 and comp_num != 0:  # dont draw self.IN.in
                        current_index = _between_brackets(translated_component)
                        bit_ind = self.cipher_instance._from_grid(
                            comp_num, current_index, model_options, input_side=True
                        )
                        bits_in[depths[comp_num]][bit_ind] = solution_bit_value
                    elif bool2:
                        current_index = _between_brackets(translated_component)
                        bit_ind = self.cipher_instance._from_grid(
                            comp_num, current_index, model_options, input_side=False
                        )
                        bits_out[depths[comp_num]][bit_ind] = solution_bit_value
        elif model_options.optimization == OPTIMIZATION.SAT:
            # NOTE: SAT-vars start at 1 while grid-indexing starts at 0
            for s, solution_bit_value in results.items():
                if s <= self.cipher_instance.input_length + self.cipher_instance.output_length:
                    # if s is SAT_IN or SAT_OUT, we skip it
                    continue
                comp_num = 0
                try:
                    # determine correct comp_num based on s being in
                    # dictionaries[comp_num]
                    while str(s) not in dictionaries[comp_num].keys():
                        comp_num += 1
                except IndexError as error:
                    # if the variable comes from the summation logic that bound
                    # the objective value, we skip it this is the case when s
                    # was added into the sat after the last component,
                    # i.e. when s > max(dictionaries[-1].keys())
                    if s > int(max(dictionaries[comp_num - 1].keys())):
                        continue
                    else:
                        raise error

                translated_component = dictionaries[comp_num][str(s)]
                comp = nodes[comp_num]
                # Draw the input nodes of each component
                bool1 = translated_component <= comp.input_length
                # We also draw the output of the last component.
                bool2 = comp.input_length < translated_component and \
                    translated_component <= comp.input_length + comp.output_length

                if bool1 and comp_num != 0:  # dont draw self.IN.in
                    current_index = translated_component - 1
                    bit_ind = self.cipher_instance._from_grid(
                        comp_num, current_index, model_options, input_side=True
                    )
                    bits_in[depths[comp_num]][bit_ind] = solution_bit_value
                elif bool2:
                    current_index = translated_component - \
                        nodes[comp_num].input_length - 1
                    bit_ind = self.cipher_instance._from_grid(
                        comp_num, current_index, model_options, input_side=False
                    )
                    bits_out[depths[comp_num]][bit_ind] = solution_bit_value

        # realign bits_in, bits_out by removing any 'None' entries
        bits_in = [
            [entry for entry in bits_in_row if entry is not None]
            for bits_in_row in bits_in
        ]
        bits_out = [
            [entry for entry in bits_out_row if entry is not None]
            for bits_out_row in bits_out
        ]

        self.input = bits_out[0]
        self.output = bits_out[-1]
        ################################################
    
        # Recursively iterate through each subcipher
        for comp_num, comp in enumerate(nodes):
            if not isinstance(comp, Component):
                if model_options.optimization == OPTIMIZATION.MILP:
                    # Build nested sub_results for the sub-cipher directly
                    # from the parent's nested results entry for this comp_num
                    sub_results = {}
                    var_name = f"X{comp_num}"
                    for s_ind, solution_bit_value in \
                            results.get(var_name, {}).items():
                        translated = dictionaries[comp_num][
                            f"{var_name}[{s_ind}]"
                        ]
                        tr_name, tr_rest = translated.split('[', 1)
                        tr_ind = int(tr_rest.rstrip(']'))
                        sub_results.setdefault(tr_name, {})[tr_ind] = \
                            solution_bit_value
                else:  # SAT
                    sub_results = {}
                    for s, solution_bit_value in results.items():
                        if check_condition(comp_num, s):
                            # Translate the results using the corresponding
                            # dictionaries
                            sub_results[dictionaries[comp_num][s]] = \
                                solution_bit_value

                self.children.append(TrailNode(
                        self.cipher_instance.nodes[depths[comp_num]],
                        model_options=model_options,
                        results=sub_results
                ))
        ########################################################################

        

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
