from sage.modules.free_module_element import vector
from sage.rings.finite_rings.finite_field_constructor import GF
from civerly.util import vec_to_int

import json
from civerly.component import Component
from civerly.model_options import OPTIMIZATION, GRANULARITY
from civerly.util import _between_brackets

class TrailNode:
    def __init__(self, cipher_instance, model_options, results_and_weight,
                 _parent_depth=None) -> None:
        r"""
        Initialize the recursive TrailNode structure, which contains the results 
        of the last analysis with CiVerLy.
        Called in :meth:`Cipher.analysis` and automatically adds
        the `.results` attribute to `cipher_instance` and its subciphers.

        INPUT:

            - cipher_instance -- the cipher instance from which this trail is from

            - model_options -- see :class:`MODEL_OPTIONS`

            - results -- list containing the solver results, coming from :meth:`Cipher.read_results`
            
            - _parent_depth -- internally used to measure the recursion depth

        OUTPUT: The root node of the tree-like structure, containing the results in a structured way.

        TEST:

        Initialize model options:

            sage: from civerly.cipher_implementations.speck import SPECK_CVL
            sage: from civerly.model_options import * 
            sage: import tempfile
            sage: # optional - cryptominisat # optional - espresso
            sage: with tempfile.TemporaryDirectory(delete=False) as tmpdir:
            ....:   cipher = SPECK_CVL(32, 64, R=4)
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.LINEAR,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     sat_solver=CRYPTOMINISAT_CVL(),
            ....:     logic_minimizer=ESPRESSO_CVL(),
            ....:     path=Path(tmpdir))
        
        Solve the model and retrieve results:

            sage: # optional - cryptominisat # optional - espresso
            sage: cipher.model(model_options)
            1792 variables and 4581 clauses were written to ...
            sage: model_options.sat_solver.solve(
            ....:    model_options.path / (cipher.name + ".cnf"),
            ....:    model_options.path / (cipher.name + ".sat"),
            ....:    model_options=model_options,
            ....:    time_limit=None)
            ...
            sage: results_and_weight = cipher.read_results(model_options)
            sage: cipher.results == []
            True
            
        Initialize TrailNode:
            
            sage: # optional - cryptominisat # optional - espresso
            sage: from civerly.trail import TrailNode
            sage: node = TrailNode(cipher, model_options, results_and_weight)
            sage: cipher.results[0]
            {'in': [...], 'out': [...], 'weight': ...}
            sage: import shutil 
            sage: shutil.rmtree(tmpdir)
        
        """
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

        cipher_instance.trail_nodes.append(self)
        results, self.weight = results_and_weight

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

        # Set .results on this cipher and each of its direct nodes
        self.cipher_instance.results.append(
            {"in": self.input, "out": self.output, "weight": self.weight}
        )
        # for comp_num, comp in enumerate(nodes):
        #     comp.results.append(_node_results[comp_num])
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
                # Compute the weight of this subcipher's trail from the
                # parent's objective contributions for comp_num.
                prefix = f"X{comp_num}["
                if hasattr(self.cipher_instance, 'sum_arr_milp'):
                    sub_weight = sum(
                        -factor * int(results.get(f"X{comp_num}", {}).get(
                            int(v[len(prefix):-1]), 0
                        ))
                        for factor, v in self.cipher_instance.sum_arr_milp
                        if v.startswith(prefix)
                    )
                else:
                    sub_weight = 0
            else:  # SAT
                sub_results = {}
                for s, solution_bit_value in results.items():
                    if check_condition(comp_num, s):
                        # Translate the results using the corresponding
                        # dictionaries
                        sub_results[dictionaries[comp_num][s]] = \
                            solution_bit_value
                # Compute the weight of this subcipher's trail from the
                # parent's objective contributions for comp_num.
                if hasattr(self.cipher_instance, 'sum_arr_sat'):
                    comp_vars = set(dictionaries[comp_num].keys())
                    pr = model_options.sat_precision
                    sub_weight = sum(
                        factor * results.get(sat_var, 0)
                        for factor, sat_var in self.cipher_instance.sum_arr_sat
                        if sat_var in comp_vars
                    ) / (10 ** pr)
                else:
                    sub_weight = 0
            # recurse
            if not isinstance(comp, Component):
                self.children.append(TrailNode(
                    comp,
                    model_options=model_options,
                    results_and_weight=(sub_results, sub_weight),
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
        r"""

        Represent ``self`` in string format.

        TESTS:

            sage: from civerly.trail import TrailNode
            sage: from civerly.cipher_implementations.speck import SPECK_CVL
            sage: from civerly.model_options import * 
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory(delete=False) as tmpdir:
            ....:   cipher = SPECK_CVL(32, 64, R=5)
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.LINEAR,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     sat_solver=CRYPTOMINISAT_CVL(),
            ....:     logic_minimizer=ESPRESSO_CVL(),
            ....:     path=Path(tmpdir))
            sage: cipher.analyse(model_options) # optional - cryptominisat espresso
            ...
            sage: # optional - cryptominisat espresso
            sage: results_and_weight = cipher.read_results(model_options)
            sage: TrailNode(cipher, model_options, results_and_weight)
            -> speck : ... -> ...
                -> speck_round : ... -> ...
                -> speck_round : ... -> ...
                -> speck_round : ... -> ...
                -> speck_round : ... -> ...
                -> speck_round : ... -> ...
            sage: import shutil 
            sage: shutil.rmtree(tmpdir)

        Another example with some toy cipher:

            sage: from civerly.sboxcipher import SBoxCipher
            sage: from civerly.component import PermuteLayer_CVL, SBox_CVL
            sage: from sage.crypto.sbox import SBox
            sage: cipher = SBoxCipher(10, 10, name="cipher")
            sage: subcipher6 = SBoxCipher(6, 6, name="sub-cipher-6-bit")
            sage: subcipher3 = SBoxCipher(3, 3, name="sub-sub-cipher-3-bit")
            sage: subcipher4 = SBoxCipher(4, 4, name="sub-cipher-4-bit")
            sage: sbox1 = SBox_CVL(
            ....:   SBox([0, 7, 3, 5, 1, 2, 6, 4]), name="sbox1")
            sage: sbox2 = SBox_CVL(
            ....:   SBox([4, 2, 1, 7, 0, 3, 5, 6]), name="sbox2")
            sage: perm = PermuteLayer_CVL([0, 3, 1, 2], name="perm")
            sage: node = subcipher3.add_subcipher(
            ....:   sbox1, [(subcipher3.IN, (i, i)) for i in range(3)])
            sage: node = subcipher3.add_subcipher(
            ....:   sbox2, [(node, (i, i)) for i in range(3)])
            sage: subcipher3.add_output([(node, (i, i)) for i in range(3)])
            sage: node1 = subcipher6.add_subcipher(
            ....:   subcipher3, [(subcipher6.IN, (i, i)) for i in range(3)])
            sage: node2 = subcipher6.add_subcipher(
            ....:   subcipher3, [(subcipher6.IN, (i + 3, i)) for i in range(3)])
            sage: subcipher6.add_output(
            ....:   [(node1, (i, i)) for i in range(3)])
            sage: subcipher6.add_output(
            ....:   [(node2, (i, i + 3)) for i in range(3)])
            sage: node = subcipher4.add_subcipher(
            ....:   perm, [(subcipher4.IN, (i, i)) for i in range(4)])
            sage: node = subcipher4.add_subcipher(
            ....:   perm, [(node, (i, i)) for i in range(4)])
            sage: subcipher4.add_output(
            ....:   [(node, (i, i)) for i in range(4)])
            sage: node1 = cipher.add_subcipher(
            ....:   subcipher6, [(cipher.IN, (i, i)) for i in range(6)])
            sage: node2 = cipher.add_subcipher(
            ....:   subcipher4, [(cipher.IN, (i + 6, i)) for i in range(4)])
            sage: cipher.add_output(
            ....:   [(node1, (i, i)) for i in range(6)])
            sage: cipher.add_output(
            ....:   [(node2, (i, i + 6)) for i in range(4)])

    Analyse the cipher:

            sage: # optional - scip
            sage: from civerly.model_options import *
            sage: from pathlib import Path
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.MILP,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND,
            ....:     milp_solver=SCIP_CVL(),
            ....:     path=Path(tmpdir))
            sage: cipher.analyse(model_options)
            206 variables and 1711 constraints were written to ...
            0
            sage: cipher.get_trail(model_options)
            -> cipher : 00... -> 00...
                -> sub-cipher-6-bit : 00 -> 00
                    -> sub-sub-cipher-3-bit : 0 -> 0
                    -> sub-sub-cipher-3-bit : 0 -> 0
                -> sub-cipher-4-bit : ... -> ...

        """
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
