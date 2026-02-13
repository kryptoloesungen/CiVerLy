===
Nix
===

`Nix <https://nixos.org/>`_ is a package manager.
We kindly ask you to use it for developing CiVerLy.
This ensures that all developers of CiVerLy, as well as the CI pipeline, are using the same versions of ``sage`` and the other dependencies.

After you installed Nix and enabled `flakes <https://nixos.wiki/wiki/Flakes>`_ you can simply clone the CiVerLy repo and then run:

.. code-block:: console

   $ nix develop

This will drop you in a shell with everything setup ready to go.
