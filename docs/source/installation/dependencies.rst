==========================================
CiVerLy Dependencies and Supported Solvers
==========================================

SageMath
========
CiVerLy is built on top of SageMath.
Hence, you must install SageMath.
For this, check out the `sage installation manual <https://doc.sagemath.org/html/en/installation/index.html>`_.
Alternatively, you can use the provided docker image or the provided AppImage.
They include not only CiVerLy but also SageMath and most of the supported solvers.

GLPK
====

`GLPK <https://www.gnu.org/software/glpk/>`_, the GNU Linear Programming Kit, is as MILP solver.
GLPK is is rather slow.
If possible, use another MILP solver.
GLPK is included in the Docker images and in the AppImage.

SCIP
====

`SCIP <https://scipopt.org/>`_ is another MILP solver.
We recommend using SCIP if you do not have access to a commercial MILP solver.
SCIP is included in the Docker images and in the AppImage.

Gurobi
======
`Gurobi <https://www.gurobi.com/>`_ is commercial MILP solver.
That is, a licence is required to use it.
Gurobi is non-free software and hence it is not included in the Docker images or in the AppImage.

CryptoMiniSat
=============
`CryptoMiniSat <https://github.com/msoos/cryptominisat>`_ is a SAT solver.
CryptoMiniSat is included in the Docker images and in the AppImage.

Cadical
=======
`Cadical <https://github.com/arminbiere/cadical>`_ is another SAT solver.
Cadical is included in the Docker images and in the AppImage.

Espresso
========
`Espresso <https://github.com/hadipourh/espresso>`_ is a logic minimizer.
Espresso is included in the Docker images and in the AppImage.
