Exporting the Results
=======================

CiVerLy supports exporting the model of a cipher, together with the trails
found by :meth:`analyse`, into a json file. The model consists of the
``MILP_CVL`` or ``SAT_CVL`` problems (see :class:`civerly.problem.Problem_CVL`)
of the cipher and of all its subciphers and components.

The structure of the cipher itself is not exported, as it is given by the code
constructing it. Instead, the exported file is loaded into a newly
constructed, identical cipher. Neither the results nor the model have to be
computed again then.

.. code-block::

    sage: # optional - scip, espresso
    sage: # First, analyse some cipher
    sage: from civerly.cipher_implementations.present import PRESENT_CVL
    sage: from civerly.model_options import *
    sage: import tempfile
    sage: tmpdir = Path(tempfile.mkdtemp())
    sage: cipher = PRESENT_CVL(4)
    sage: model_options = MODEL_OPTIONS(
    ....:     optimization=OPTIMIZATION.MILP,
    ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
    ....:     granularity=GRANULARITY.BITWISE,
    ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
    ....:     milp_solver=SOLVER.SCIP,
    ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.MORE_DUMMIES,
    ....:     logic_minimizer=SOLVER.ESPRESSO,
    ....:     path=tmpdir
    ....: )
    sage: cipher.analyse(model_options)
    5312 variables and 8641 constraints were written to ...
    12
    sage: # Export the model together with the results
    sage: cipher.export(tmpdir / "present.json")
    sage: # Load them into a new instance of the same cipher
    sage: loaded = PRESENT_CVL(4).load(tmpdir / "present.json")
    sage: # The results are still the same
    sage: loaded.result["objective_value"]
    12
    sage: trail = loaded.get_trail(model_options)
    sage: trail.input == cipher.get_trail(model_options).input
    True
    sage: import shutil
    sage: shutil.rmtree(tmpdir)
