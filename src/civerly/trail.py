from sage.modules.free_module_element import vector
from sage.rings.finite_rings.finite_field_constructor import GF
from civerly.util import vec_to_int

import json
from civerly.component import Component
from civerly.model_options import OPTIMIZATION, GRANULARITY
from civerly.util import _between_brackets

class TrailNode:
    def __init__(self, cipher_instance, model_options, results,
                 _parent_depth=None) -> None:
        self.children : list[TrailNode] = []
        self.right = None
        self.input = None
        self.output = None
        self.bits_in = None
        self.bits_out = None
        self._parent_depth = _parent_depth
        self.cipher_instance = cipher_instance
        self.name = cipher_instance.name
        self.input_length = cipher_instance.input_length
        self.output_length = cipher_instance.output_length

        # obtain dictionaries
        opt_to_attr = {OPTIMIZATION.MILP: 'dictionaries_milp', OPTIMIZATION.SAT: 'dictionaries_sat'}
        attr = opt_to_attr[model_options.optimization]
        if hasattr(self.cipher_instance, attr):
            dictionaries = getattr(self.cipher_instance, attr)
        else:
            with open(model_options.path / (self.name + "_d.json")) as f:
                dictionaries = json.load(f)

        if model_options.optimization == OPTIMIZATION.SAT:
            def check_condition(comp_num, s):
                return s > self.cipher_instance.input_length + self.cipher_instance.output_length and \
                    s in dictionaries[comp_num].keys()

        depths = self.cipher_instance._dfs_traversal()
        nodes = self.cipher_instance.nodes

        ################################################
        depth_range = range(max(depths) + 1)
        max_width_in = max(
            sum(n.input_length for n, d in zip(nodes, depths) if d == depth)
            for depth in depth_range
        )
        max_width_out = max(
            sum(n.output_length for n, d in zip(nodes, depths) if d == depth)
            for depth in depth_range
        )

        divide_by = self.cipher_instance.wordsize if model_options.granularity == GRANULARITY.WORDWISE else 1

        bits_in  = [[None] * (max_width_in  // divide_by) for _ in depth_range]
        bits_out = [[None] * (max_width_out // divide_by) for _ in depth_range]

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
                    while s not in dictionaries[comp_num].keys():
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

                translated_component = dictionaries[comp_num][s]
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

        # Extract per-node result slices before None removal changes indexing
        grid_in  = self.cipher_instance._construct_grid(divide_by=divide_by, input_side=True)
        grid_out = self.cipher_instance._construct_grid(divide_by=divide_by, input_side=False)
        _node_results = {}
        for comp_num, comp in enumerate(nodes):
            d = depths[comp_num]
            comp_bits_in  = [bits_in[d][i]  for i, (n, _) in enumerate(grid_in[d])  if n == comp_num and bits_in[d][i]  is not None]
            comp_bits_out = [bits_out[d][i] for i, (n, _) in enumerate(grid_out[d]) if n == comp_num and bits_out[d][i] is not None]
            _node_results[comp_num] = {"in": comp_bits_in, "out": comp_bits_out}

        # realign bits_in, bits_out by removing any 'None' entries
        bits_in  = [[e for e in row if e is not None] for row in bits_in]
        bits_out = [[e for e in row if e is not None] for row in bits_out]

        self.bits_in  = bits_in
        self.bits_out = bits_out
        self.input  = bits_out[0]
        self.output = bits_out[-1]

        # Set .result on this cipher and each of its direct nodes
        self.cipher_instance.result = {"in": self.input, "out": self.output}
        for comp_num, comp in enumerate(nodes):
            comp.result = _node_results[comp_num]
        ################################################

        # Iterate through each subcipher
        for comp_num, comp in enumerate(nodes):
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
            # recurse
            if not isinstance(comp, Component):
                self.children.append(TrailNode(
                    comp,
                    model_options=model_options,
                    results=sub_results,
                    _parent_depth=depths[comp_num]
                ))

        # link siblings
        for i in range(len(self.children) - 1):
            self.children[i].right = self.children[i + 1]
        ########################################################################
        assert len(self.bits_out[0]) == len(self.input)
        assert len(self.bits_out[-1]) == len(self.output)


    def _to_hex(self) -> str:
        string = ""
        if self.output is not None:
            string += f"{vec_to_int(
                vector(GF(2), self.input)
            ):0{(self.input_length + 3)//4}x}"
        else:
            string += "None"
        string += " -> "
        if self.output is not None:
            string += f"{vec_to_int(
                vector(GF(2), self.output)
            ):0{(self.output_length + 3)//4}x}"
        else:
            string += "None"
        return string

    def __repr__(self, _depth=0) -> str:
        from civerly.cipher import Cipher
        string = "\t"*_depth + "-> " + f"{self.name} : {self._to_hex()}"
        for child in self.children:
            if not isinstance(
                child.cipher_instance, Cipher._Cipher__Special_Node
            ):
                string += "\n" + child.__repr__(_depth+1)
        return string

    def to_latex(self, model_options) -> str:
        string = self.cipher_instance._latex_section(self, model_options)
        for child in self.children:
            string += child.to_latex(model_options)
        return string

    def verify_correctness(self):
        r"""
        Performs a coherence check of the report. For each sub-cipher child,
        it verifies that the intermediate states seen from the parent cipher
        and from the sub-cipher itself agree.

        As an example, for ExampleRound = [LinearLayer, SBoxLayer] the
        following must hold (labelling states as in the report):

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

        Checks: (1)==(4), (2)==(5), (2)==(6), (3)==(7).

        For each child at depth d in the parent, this amounts to:
            parent.bits_in[d]   == child.bits_out[0]    (input match)
            parent.bits_out[d]  == child.bits_out[-1]   (output match)

        Note that this is a purely syntactic verification of the report, there
        is no validation on a semantic level!
        """

        valid = True

        if not self.children or None in (self.input, self.output):
            return valid

        dmax = 1 + max([child._parent_depth for child in self.children])
        off_in  = [0]*dmax
        off_out = [0]*dmax

        for child in self.children:
            d = child._parent_depth

            expected_in  = self.bits_in[d][off_in[d] : off_in[d] + len(child.input)]
            expected_out = self.bits_out[d][off_out[d] : off_out[d] + len(child.output)]
            actual_in    = child.bits_out[0]
            actual_out   = child.bits_out[-1]

            off_in[d]  += len(child.input)
            off_out[d] += len(child.output)

            if expected_in and actual_in and expected_in != actual_in:
                raise AssertionError(
                    f"Report is not coherent between {self.name} and "
                    f"{child.name} (input at depth {d}): "
                    f"(parent = {expected_in}) | (child = {actual_in})."
                )
            if expected_out and actual_out and expected_out != actual_out:
                raise AssertionError(
                    f"Report is not coherent between {self.name} and "
                    f"{child.name} (output at depth {d}): "
                    f"(parent = {expected_out}) | (child = {actual_out})."
                )

            child.verify_correctness()

        return
