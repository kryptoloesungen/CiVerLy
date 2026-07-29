r"""
The ``SBoxCipher`` class, a subclass of ``Cipher`` allowing only
specific operations.

The ``SBoxCipher`` class inherits most of its functionality from ``Cipher``,
with the restriction that only ``sub_ciphers`` of the type ``SBoxCipher,
SBox_CVL, LinearLayer_CVL, XOR_CVL, RK_CVL, C_CVL`` are allowed (or its
subclasses).

The purpose of this subclass is to allow for MILP modeling, which is not
supported for ciphers containing different non-linear components than
``SBox_CVL``, such as ``AddRX, AndRX``.
"""

import json
from dataclasses import replace

from civerly.milp import MILP_CVL
from civerly.cipher import Cipher
from civerly.component import SBox_CVL, LinearLayer_CVL, XOR_CVL
from civerly.component import RK_CVL, C_CVL, I_CVL, RoundkeyXOR_CVL, ConstXOR_CVL
from civerly.util import suppress_output
from civerly.util import translate_milp_constraint
from civerly.util import translate_var
from civerly.model_options import OPTIMIZATION, GRANULARITY, CRYPTANALYSIS
from civerly.model_options import InvalidModelOptionException


class SBoxCipher(Cipher):

    def __init__(self, input_length, output_length, name):
        r"""
        .. SEEALSO::
            - :meth:`civerly.cipher.Cipher.__init__` for the initialization
              details.
        """
        super().__init__(input_length, output_length, name)

    def add_subcipher(self, sub_cipher, edges):
        r"""
        Check whether ``sub_cipher`` is allowed in ``SBoxCipher`` before
        calling :meth:`civerly.cipher.Cipher.add_subcipher`.
        """
        if isinstance(sub_cipher, (
            SBoxCipher, SBox_CVL, LinearLayer_CVL,
            XOR_CVL, RK_CVL, C_CVL, I_CVL, RoundkeyXOR_CVL, ConstXOR_CVL
        )):
            return super().add_subcipher(sub_cipher, edges)
        else:
            raise TypeError(
                f"The passed sub_cipher has type {type(sub_cipher)} and is "
                "not allowed in SBoxCiphers."
            )

    def _to_dict(self):
        d = super()._to_dict()
        d["type"] = "SBoxCipher"
        return d

    def _model_milp(self, model_options, _first_iter=False):
        r"""
        Generate the model for ``self`` according to the given
        ``model_options``.

        INPUT:

            - ``model_options`` -- see
              :class:`civerly.model_options.MODEL_OPTIONS`

        We first generate a ``master_milp``, recursively iterate over
        ``self.nodes`` (and its subciphers) and collect the sub-milps in
        order to relabel and connect them correctly to one big milp. To avoid
        remodeling the same components multiple times, a caching-mechanism is
        implemented which checks if the currently modeled component was
        modeled before. If yes, the milp will be copied over instead of being
        generated from scratch again.

        TESTS:

            Model toy Feistel cipher to test branching::

                sage: from civerly.sboxcipher import SBoxCipher
                sage: from civerly.component import SBox_CVL, XOR_CVL
                sage: from civerly.component import RoundkeyXOR_CVL
                sage: from civerly.model_options import *
                sage: from sage.crypto.sboxes import PRESENT as present_S_sage
                sage: from civerly.util import suppress_output
                sage: import tempfile
                sage: from pathlib import Path
                sage: tmpdir = tempfile.mkdtemp()
                sage: name = "ToyFeistel"
                sage: n = 4
                sage: R = 1
                sage: round = SBoxCipher(2*n, 2*n, name=name+"Round")
                sage: sbox = SBox_CVL(present_S_sage, "s-box")
                sage: xor = XOR_CVL(n, name="xor")
                sage: key_add = RoundkeyXOR_CVL(n, 0, name="key_add")
                sage: node_sbox = round.add_subcipher(
                ....:   sbox, [(round.IN, (i, i)) for i in range(n)])
                sage: node_xor  = round.add_subcipher(xor, [
                ....:   (node_sbox, (i, i)) for i in range(n)] + [
                ....:   (round.IN, (i, i)) for i in range(n, 2*n)])
                sage: node_keyxor = round.add_subcipher(
                ....:   key_add, [(node_xor, (i, i)) for i in range(n)])
                sage: node_kx = round.add_subcipher(
                ....:   key_add, [(round.IN, (i, i)) for i in range(n)])
                sage: round.add_output([
                ....:   (node_keyxor, (i, i)) for i in range(n)
                ....: ] + [(node_kx, (i, i + n)) for i in range(n)])
                sage: cipher = SBoxCipher(2*n, 2*n, name=name+"Cipher")
                sage: node = cipher.IN
                sage: for r in range(R):
                ....:   node = cipher.add_subcipher(
                ....:   round, [(node, (i, i)) for i in range(2*n)]
                ....: )
                sage: cipher.add_output([(node, (i, i)) for i in range(2*n)])
                sage: model_options = MODEL_OPTIONS(
                ....:   cryptanalysis=CRYPTANALYSIS.LINEAR,
                ....:   optimization=OPTIMIZATION.MILP,
                ....:   granularity=GRANULARITY.BITWISE,
                ....:   linear_layer_modeling=LINEAR_LAYER_MODELING.MORE_DUMMIES,
                ....:   sbox_modeling=SBOX_MODELING.CONVEX_HULL,
                ....:   milp_solver=SOLVER.SCIP,
                ....:   path=Path(tmpdir))
                sage: cipher.analyse(model_options) # optional - scip
                135 variables and 154 constraints were written to ...
                0
                sage: R = 2
                sage: cipher = SBoxCipher(2*n, 2*n, name=name+"Cipher")
                sage: node = cipher.IN
                sage: for r in range(R):
                ....:   node = cipher.add_subcipher(
                ....:       round, [(node, (i, i)) for i in range(2*n)]
                ....:   )
                sage: cipher.add_output([(node, (i, i)) for i in range(2*n)])
                sage: model_options = MODEL_OPTIONS(
                ....:   cryptanalysis=CRYPTANALYSIS.LINEAR,
                ....:   optimization=OPTIMIZATION.MILP,
                ....:   granularity=GRANULARITY.BITWISE,
                ....:   linear_layer_modeling=LINEAR_LAYER_MODELING.MORE_DUMMIES,
                ....:   sbox_modeling=SBOX_MODELING.CONVEX_HULL,
                ....:   milp_solver=SOLVER.SCIP,
                ....:   path=Path(tmpdir))
                sage: cipher.analyse(model_options) # optional - scip
                Using existing file ..., make sure it is up to date!
                222 variables and 267 constraints were written to ...
                1
                sage: import shutil
                sage: shutil.rmtree(tmpdir) # optional - scip
        """
        if model_options.granularity == GRANULARITY.WORDWISE \
                and type(self) is SBoxCipher:
            raise InvalidModelOptionException(
                model_options.granularity,
                message="Wordwise modeling is not supported for the SBoxCipher class!"
            )

        # create the directory models are written to
        if model_options.write_to_file:
            model_options.path.mkdir(parents=True, exist_ok=True)

        # do not write the sub models to file
        model_options_ = replace(model_options, write_to_file=False)
        model_options, model_options_ = model_options_, model_options

        master_milp = MILP_CVL(maximization=False)

        # VAR_MODEL is the main MIPVariable being used
        VAR_MODEL = [
            master_milp.new_variable(binary=True, name=f"X{i}")
            for i in range(len(self.nodes))
        ]
        self.sum_arr_milp = []

        # dictionaries for translating variables in sage and the mps file
        self.dictionaries_milp = [{} for _ in range(len(self.nodes))]
        self.inv_dictionaries_milp = [{} for _ in range(len(self.nodes))]

        for i_comp, comp in enumerate(self.nodes):
            # check if component was modeled before
            for i_prev, prev in enumerate(self.nodes[:i_comp]):
                if comp == prev:
                    # copy the component entirely (and its attributes!)
                    self.nodes[i_comp] = self.nodes[i_prev]
                    comp = prev

                    # recursively copy component dictionaries
                    comp._copy_over_dictionaries_recursively(
                        prev, model_options)
                    break
            else:
                # model the components that have not been modeled before
                comp.model(model_options, _first_iter=False)

            ##################################################################
            # parse the component MILP and adopt it into the master milp     #
            ##################################################################
            self.dictionaries_milp[i_comp] = master_milp.append(
                comp.milp, VAR_MODEL[i_comp]
            )
            self.inv_dictionaries_milp[i_comp] = {
                v: k for k, v in self.dictionaries_milp[i_comp].items()
            }

            # translate the objective variables
            self.sum_arr_milp += [
                (factor, self.inv_dictionaries_milp[i_comp][entry])
                for factor, entry in comp.sum_arr_milp
            ]

        ######################################################
        #    -> Connect the MILPs with each other.           #
        ######################################################

        # -------------- set VAR_IN and VAR_OUT variables ---------------- #
        if model_options.granularity == GRANULARITY.BITWISE:
            divide_by = 1
        elif model_options.granularity == GRANULARITY.WORDWISE:
            divide_by = self.wordsize

        __ASSERTION_CTR = 0
        for x in range(self.input_length // divide_by):
            __ASSERTION_CTR += 1

            loc_ind  = self.IN.milp.vars['OUT'].get_index(x)
            glob_ind = self.inv_dictionaries_milp[self.nodes.index(self.IN)][loc_ind]
            compMILP_INx = master_milp.get_var(glob_ind)
            master_milp.add_constraint(master_milp.VAR_IN[x] == compMILP_INx)

        assert __ASSERTION_CTR == self.input_length // divide_by, (
            f"({self.name}) "
            f"{__ASSERTION_CTR} != {self.input_length // divide_by}"
        )

        # (wordwise) edges connected to output
        output_arr = [
            (y//divide_by, (a, x//divide_by))
            for (y, (a, x)) in enumerate(self.outputs)
        ]

        __ASSERTION_CTR = 0
        for y, (a, x) in set(output_arr):  # if comp is connected to output
            __ASSERTION_CTR += 1

            loc_ind  = self.nodes[a].milp.vars['OUT'].get_index(x)
            glob_ind = self.inv_dictionaries_milp[a][loc_ind]
            var = master_milp.get_var(glob_ind)
            master_milp.add_constraint(var == master_milp.VAR_OUT[y])
            # NOTE watch out for what happens with the case below:
            # if input is directly connected to output. Without this, there
            # does not exist a corresponding edge, which is why this case
            # would be ignored when modeled. In this case, connect in- and
            # output directly.
            # if a == self.nodes.index(self.IN):
            #     cmi = self.inv_dictionaries_milp[
            #         self.nodes.index(self.IN)][f'OUT[{x}]']


        assert __ASSERTION_CTR == self.output_length // divide_by, (
            f"({self.name}) "
            f"{__ASSERTION_CTR} != {self.output_length // divide_by}"
        )

        # -------------- Find comp.IN/OUT and connect these ---------------- #
        # dictionary of branches with key in_node and
        # value[out_node0, out_node1, ...]
        branches = dict()

        edge_arr = set([
            ((aa, bb), (xx//divide_by, yy//divide_by))
            for ((aa, bb), (xx, yy)) in self.edges
        ])

        # take the (wordwise) edges in the graph to combine the MILPs
        for (a, b), (x, y) in edge_arr:
            loc_ind  = self.nodes[a].milp.vars['OUT'].get_index(x)
            glob_ind = self.inv_dictionaries_milp[a][loc_ind]
            aOUTx = master_milp.get_var(glob_ind)

            loc_ind  = self.nodes[b].milp.vars['IN'].get_index(y)
            glob_ind = self.inv_dictionaries_milp[b][loc_ind]
            bINy = master_milp.get_var(glob_ind)

            if aOUTx not in branches:
                branches[aOUTx] = []
            branches[aOUTx].append(bINy)
        # ------------------------------------------------------------------ #
        for in_node, out_nodes in branches.items():
            assert len(out_nodes) != 0, (
                f"Component {in_node} needs to have an output!"
            )

            if model_options.cryptanalysis == CRYPTANALYSIS.DIFFERENTIAL:
                # All output branches receive the difference of
                # the input branch
                for out_node in out_nodes:
                    # Connect the now translated variables corresponding
                    # to the output/input of some subcipher
                    master_milp.add_constraint(in_node == out_node)
            elif model_options.cryptanalysis == CRYPTANALYSIS.LINEAR:
                if len(out_nodes) > 2:
                    from civerly.component import LinearLayer_CVL
                    from civerly.model_options import MODEL_OPTIONS
                    from civerly.model_options import LINEAR_LAYER_MODELING
                    from sage.matrix.constructor import Matrix as matrix

                    # Linear model of n-branching == Differential model
                    # of n-XOR
                    mat = matrix([1]*len(out_nodes))

                    branching = LinearLayer_CVL(mat)
                    branching_milp = branching._model_milp(MODEL_OPTIONS(
                        cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
                        optimization=OPTIMIZATION.MILP,
                        granularity=GRANULARITY.BITWISE,
                        linear_layer_modeling=LINEAR_LAYER_MODELING.CONVEX_HULL
                    ))
                    branching_nodes = out_nodes + [in_node]
                    # copy over the constraints generated by ``LinearLayer_CVL``
                    for constr in branching_milp.constraints():
                        master_milp.add_constraint(
                            translate_milp_constraint(branching_nodes, constr)
                        )

                elif len(out_nodes) == 2:
                    # Model branching analog to XOR_CVL in the
                    # differential setting
                    if model_options.granularity == GRANULARITY.BITWISE:
                        master_milp.add_constraint(
                            -in_node + out_nodes[0] + out_nodes[1] >= 0
                        )
                        master_milp.add_constraint(
                            in_node - out_nodes[0] + out_nodes[1] >= 0
                        )
                        master_milp.add_constraint(
                            in_node + out_nodes[0] - out_nodes[1] >= 0
                        )
                        master_milp.add_constraint(
                            -in_node - out_nodes[0] - out_nodes[1] >= -2
                        )
                    if model_options.granularity == GRANULARITY.WORDWISE:
                        master_milp.add_constraint(
                            -in_node + out_nodes[0] + out_nodes[1] >= 0
                        )
                        master_milp.add_constraint(
                            in_node - out_nodes[0] + out_nodes[1] >= 0
                        )
                        master_milp.add_constraint(
                            in_node + out_nodes[0] - out_nodes[1] >= 0
                        )
                        # Skip fourth constraint as we are working with
                        # activity patterns instead of values
                else:  # len(out_nodes) == 1
                    master_milp.add_constraint(out_nodes[0] == in_node)
            else:
                raise InvalidModelOptionException(
                    model_options.cryptanalysis,
                    CRYPTANALYSIS
                    )
        # ------------------------------------------------------------------- #

        # set all "dangling" nodes to zero (especially important
        # for linear cryptanalysis)
        ax_arr = [(a, x) for (a, b), (x, y) in self.edges]
        for a in range(len(self.nodes)):
            for x in range(self.nodes[a].output_length):
                if (a, x) not in ax_arr + self.outputs:
                    if isinstance(
                        self.nodes[a], SBoxCipher._Cipher__Special_Node
                    ) and not self.nodes[a].in_node:
                        pass  # skip OUT-nodes
                    else:
                        loc_ind  = self.nodes[a].milp.vars['OUT'].get_index(x)
                        glob_ind = self.inv_dictionaries_milp[a][loc_ind]
                        master_milp.add_constraint(master_milp.get_var(glob_ind) == 0)

        # change back s.t. toplevel milp is written to file
        model_options, model_options_ = model_options_, model_options

        master_milp.VAR_MODEL = VAR_MODEL

        return self._finish_milp(model_options, master_milp,
                                 _first_iter=_first_iter)

    def _finish_milp(self, model_options, milp, _first_iter=False):
        r"""
        Finish the given ``MILP_CVL``. That is, add a
        constraint that ensures that the input is active and add the objective
        function.
        If specified by ``model_options``, write the model to a file.

        INPUT:

            - ``model_options`` -- see
              :class:`civerly.model_options.MODEL_OPTIONS`
            - ``milp`` -- ``MILP_CVL``; the milp to be
              finished

        OUTPUT:

            - The generated MILP model, describing the possible differential
              propagations through ``self``.

        .. WARNING::
            If specified by ``model_options``, this method does not only write
            the model to file but also implicitly generates ``.json`` files in
            the same location, with similar names (``<self.name>_d.json`` and
            ``<self.name>_id.json``).
            These are necessary to translate the abstract ``.mps`` file content
            into a meaningful MILP and is therefore used in ``generate_report``
            to be able to generate the report correctly.
        """
        if model_options.optimization != OPTIMIZATION.MILP:
            raise InvalidModelOptionException(
                model_options.optimization,
                OPTIMIZATION
                )

        summation_result = 0  # Construct the objective
        # sum_arr contains:
        # - the variables that correspond to an SBox being active
        #   or not (wordwise)
        # - the variables and the corresponding propagation
        #   probability (bitwise)
        for factor, entry in self.sum_arr_milp:
            # negative factor since we want to MINIMIZE the MILP
            # while MAXIMIZING the propagation probability.

            summation_result += -factor * milp.get_var(entry)

        if len(milp.VAR_IN.items()) == 0:
            raise ValueError("Empty MILP")

        if _first_iter:
            # Input should be active, i.e. the input
            # differences should be non-zero
            milp.add_constraint(milp.sum(milp.vars['IN']) >= 1)

            # bound the objective by `model_options.solve_range``
            if model_options.solve_range is not None:
                milp.add_constraint(
                    model_options.solve_range[0]
                    <= summation_result
                    <= model_options.solve_range[1]
                )

            # Minimize the sum of all (relevant) entries
            milp.set_objective(summation_result)

        # Save the dictionary files as json
        with open(model_options.path / (self.name + "_d.json"), 'w') as f:
            json.dump(self.dictionaries_milp, f)
            f.close()

        with open(model_options.path / (self.name + "_id.json"), 'w') as f:
            json.dump(self.inv_dictionaries_milp, f)
            f.close()

        if model_options.write_to_file:
            print(
                f"{milp.number_of_variables()} variables and "
                f"{milp.number_of_constraints()} constraints were written to "
                f"'{str(model_options.path / (self.name + '.mps'))}'"
            )
            with suppress_output():
                milp.write_mps(str(model_options.path / (self.name + ".mps")))

        self.milp = milp
        return milp

    def _exclude_solution_milp(self, results: dict) -> None:
        r"""
        Convert a MILP solution *results* dict (as returned by
        ``_process_solution_file``) into a constraint which forbids this
        solution and add it to ``self.milp``.

        This ensures the exact solution cannot be found again on re-solve.
        The constraint is added directly to ``self.milp``; callers must
        flush ``self.milp`` to the MPS file (via ``_finish_milp``) before
        invoking the solver again.

        TESTS::

            sage: # optional - scip espresso
            sage: from civerly.cipher_implementations.present \
            ....:   import PRESENT_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: present_cipher = PRESENT_CVL(R=4)
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.MILP,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.MORE_DUMMIES,
            ....:     milp_solver=SOLVER.SCIP,
            ....:     logic_minimizer=SOLVER.ESPRESSO,
            ....:     number_of_solutions=3,
            ....:     path=Path(tmpdir))
            ....:   present_cipher.analyse(model_options)
            5312 variables and 8641 constraints were written to ...
            [12, 12, 12]
            sage: t1, t2, t3 = present_cipher.get_trail(model_options)
            sage: t1 == t2 or t1 == t3 or t2 == t3
            False


        """
        # add \sum_{x_ij = 0} x_ij + \sum_{x_ij = 1} (1 - x_ij) \geq 1
        lhs = 0
        n_active = 0
        for var_name, sub_dict in results.items():
            if var_name in ("IN", "OUT"):
                continue
            if var_name[0] == 'X':
                # 'X3' -> 3
                i = int(var_name[1:])
            for j, val in sub_dict.items():
                assert val in (0, 1), f"{val} is not binary"
                n_active += val
                lhs += ((-1) ** val) * translate_var(
                    self, self.nodes[i], self.milp.VAR_MODEL[i][j]
                )

        self.milp.add_constraint(lhs >= 1 - n_active)
