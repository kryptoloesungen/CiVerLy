# Welcome to CiVerLy — The Cipher Verification Library

## Overview

CiVerLy helps you analyze primitives from symmetric cryptography.

![Overview of CiVerLy workflow.](docs/source/user_manual/workflow.png)

First, implement the cipher in the format CiVerLy expects. CiVerLy can then automatically apply methods from the academic literature to generate mixed-integer linear programming (MILP) or satisfiability (SAT) models that describe the linear or differential properties of the cipher. Solving these models produces linear or differential trails, which allow you to assess the security of the primitive. Check out the [ciphers already implemented in CiVerLy](src/civerly/cipher_implementations/) for examples.

CiVerLy is built on [SageMath](https://www.sagemath.org/) and is intentionally modular. For example, model generation and solving are separable, so they can run on different machines. The modular design also makes it easy to extend CiVerLy (for instance, to integrate additional cryptographic techniques).

This project was developed by [cryptosolutions GmbH](https://cryptosolutions.de/) on behalf of the [German Federal Office for Information Security (BSI)](https://www.bsi.bund.de). 
As part of the effort to strengthen IT security, CiVerLy has been released as open-source software and made freely available to the scientific community.
cryptosolutions GmbH now continues to develop and maintain the project.

## Documentation

The full documentation is available at [kryptoloesungen.github.io/CiVerLy](https://kryptoloesungen.github.io/CiVerLy).

## Installation

See `docs/build/` for the reference manual (HTML/PDF). The installation instructions are part of that manual (e.g. `docs/build/html/installation/`).

## Quickstart (Sage session)

The following example shows how to import the built‑in AES implementation, configure a simple model, and run an analysis in an interactive Sage session (after installing CiVerLy; see the docs in `docs/build/`).

1. **Start a Sage REPL**:

   ```bash
   sage
   ```

2. **Run a minimal AES analysis** (copy/paste into the Sage prompt):

   ```python
   from pathlib import Path

   # Import the AES implementation and modeling options
   from civerly.cipher_implementations.aes import AES_CVL
   from civerly.model_options import *

   # Instantiate a 10-round AES cipher
   aes = AES_CVL(R=10, name="AES-10r")

   # Configure a simple word-wise MILP model for differential cryptanalysis
   model_options = MODEL_OPTIONS(
       cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
       optimization=OPTIMIZATION.MILP,
       granularity=GRANULARITY.WORDWISE,
       linear_layer_modeling=LINEAR_LAYER_MODELING.BRANCH_NUMBER,
       solver=SOLVER.SCIP,  # requires SCIP to be installed
       path=Path("./AES-Models/"),
   )

   # Generate the model and run the solver, printing the best trail weight
   aes.analyse(model_options)
   ```

3. **Generate a PDF report from the solution**:

   After a successful run of ``aes.analyse(model_options)``, you can create a
   PDF visualization of the trail (requires a LaTeX installation, see the
   documentation for details):

   ```python
   aes.generate_report(model_options)
   ```

   This writes a ``AES-10r.pdf`` report (and an intermediate ``.tex`` file)
   into the same directory given by ``model_options.path`` (here: ``./AES-Models/``).

This will write the MILP model files into `./AES-Models/` and print, among other information, the number of active S-boxes for 10-round AES. For more examples and configuration options, see the [user manual](https://kryptoloesungen.github.io/CiVerLy/user_manual/index.html) and the [AES documentation](https://kryptoloesungen.github.io/CiVerLy/documentation/implementations/aes.html).
## License
This project is licensed under the EUROPEAN UNION PUBLIC LICENCE v. 1.2 (EUPL 1.2) with an additional non-endorsement clause; see [LICENSE](LICENSE) for details.
