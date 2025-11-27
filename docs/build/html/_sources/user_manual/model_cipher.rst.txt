===================
Modeling the Cipher
===================

After a cipher has been implemented in CiVerLy, the next step is to model the cipher.
While CiVerLy takes care of the modeling, the user has to specify what models CiVerLy shall use.
Before we give an overview of the available options and make recommendations for defaults, we briefly explain the high-level idea of the modeling procedure.

How Ciphers Are Modeled
=======================

The implementation of a cipher in CiVerLy reassembles a directed acyclic graph.
The components in the cipher (and its subciphers) are nodes in the graph and their connections are the edges.
CiVerLy uses this structure when modeling a cipher:
First, all components are modeled individually.
This is possible because the CiVerLy source code contains procedures to model all available components.
Notice that depending on the chosen model and component, this process can take some time but usually finishes in a couple of minutes.
CiVerLy then connects the individual models into one model for the complete cipher and further adds an objective function or a weight bound for MILP and SAT respectively.


Choosing the Model Options
==========================
Below, we give a exemplary code snippet that configures the model options for an CiVerLy analysis.

.. code-block::

   sage: from civerly.model_options import *
   sage: model_options = MODEL_OPTIONS(
   ....:   cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
   ....:   optimization=OPTIMIZATION.SAT,
   ....:   granularity=GRANULARITY.BITWISE,
   ....:   linear_layer_modeling=LINEAR_LAYER_MODELING.EXCLUDE_ODD,
   ....:   sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
   ....:   solver=SOLVER.CRYPTOMINISAT,
   ....:   solve_range=(0, 32),
   ....:   path=Path("Models/Cipher"))

While some of the options should be clear already from the example, e.g., ``cryptanalysis`` tells CiVerLy whether to apply differential or linear cryptanalysis, we list all available options below.
Notice that in the source code all this options are gathered in ``model_options.py`` (hence the first line in the example).

General Options
"""""""""""""""

* ``cryptanalysis``

  With this mandatory option the user chooses between differential and linear cryptanalysis.
  That is, ``cryptanalysis`` must be set to:

  * ``CRYPTANALYSIS.DIFFERENTIAL`` or
  * ``CRYPTANALYSIS.LINEAR``.

* ``optimization``

  With this mandatory option the user chooses between MILP and SAT modeling.
  That is, ``optimization`` must be set to:

  * ``OPTIMIZATION.MILP`` or
  * ``OPTIMIZATION.SAT``.

* ``granularity``

  With this mandatory option the user chooses between a bitwise and a wordwise analysis.
  For wordwise analysis, which is only implemented for MILP, we do not study the specific differences (or masks) throughout the cipher but only the activity pattern.
  This usually leads to way faster but less precise models.
  ``granularity`` must be set to:

  * ``GRANULARITY.WORDWISE`` or
  * ``GRANULARITY.BITWISE``.

* ``solver``

  With this option, the user chooses the MILP or SAT solver that CiVerLy will use.
  The supported MILP solvers are SCIP, GLPK, and Gurobi.
  For SAT, CiVerLy supports Cryptominisat and CaDiCaL.
  The solver, of course, must be installed on the same machine as CiVerLy.
  Notice that this option can also be set to None.
  CiVerLy then only generates the models and leaves it to the user to solve them.
  Hence, ``solver`` must be set to:

  * ``None`` or
  * ``SOLVER.SCIP`` or
  * ``SOLVER.GLPK`` or
  * ``SOLVER.GUROBI`` or
  * ``SOLVER.CRYPTOMINISAT`` or
  * ``SOLVER.CADICAL``.

* ``path``

  With this mandatory option the user chooses where CiVerLy will store the generated models and other files.
  That is, ``path`` is to be understand as directory or folder here and there is no link to the literal *path* in CiVerLy.
  Internally, CiVerLy relies on the Python ``pathlib`` library and hence ``path`` must be a ``pathlib.PosixPath`` instance.
  To get this, simply wrap a string describing the directory where CiVerLy should store files into ``Path()``, as in the example above.
  More information about Python's ``pathlib`` can be found `online <https://docs.python.org/3/library/pathlib.html>`_.

* ``solve_range``

  This option sets the weight interval in which CiVerLy will generate SAT models.
  For SAT this default to (0, 100), i.e., by default CiVerLy trails with weight 0 to 100 which is usually is a reasonable range.
  Hence, you can mostly ignore this option for SAT.
  Ignore this options for MILP.

* ``sat_precision``

  For certain S-boxes the SAT modeling in CiVerLy is an approximation. This integer parameter determines the precision, i.e., the number of decimal places that are used for the approximation.
  This default to 0.
  Increasing it will have a drastic impact on performance.

Techniques to model Components
"""""""""""""""""""""""""""""""

For certain components, namely linear layers and S-boxes, CiVerLy supports different modeling techniques.
We list the corresponding keys below.
Of course, if a cipher does not contain any S-box or no linear layer component, then the corresponding options does not have to be set.

* ``linear_layer_modeling``

  When set, this must be one of:

  * ``LINEAR_LAYER_MODELING.BRANCH_NUMBER`` or
  * ``LINEAR_LAYER_MODELING.GENERALIZED_WORDWISE`` or
  * ``LINEAR_LAYER_MODELING.CONVEX_HULL`` or
  * ``LINEAR_LAYER_MODELING.MORE_DUMMIES`` or
  * ``LINEAR_LAYER_MODELING.EXCLUDE_ODD``.

* ``sbox_modeling``

  When set, this must be one of:

  * ``SBOX_MODELING.CONVEX_HULL`` or
  * ``SBOX_MODELING.LOGICAL_COND`` or
  * ``SBOX_MODELING.DISTORTED_BALL`` or
  * ``SBOX_MODELING.LOGICAL_COND_ESPRESSO``.


Recommendations
===============

Giving general recommendations is, of course, not easy.
As every cipher is different, we must expect cases where the foloowing recommendations are non-optimal.
Therefore, we strongly recommend to try different options on small instances of a cipher before modeling real instances.

For AES-like ciphers, i.e., cipher consisting of an S-box layer, a step permuting the cells and a MixColumns step, we recommend to use wordwise MILP modeling with the ``GENERALIZED_WORDWISE`` linear layer modeling.
To keep it simple, for everything else we recommend bitwise SAT modeling with the ``MORE_DUMMIES`` linear layer modeling and the ``LOGICAL_COND_ESPRESSO`` modeling for S-boxes.

In terms of solvers, for MILP, we recommend SCIP (unless a Gurobi licence is already available).
For SAT, we recommend Cryptominisat.
