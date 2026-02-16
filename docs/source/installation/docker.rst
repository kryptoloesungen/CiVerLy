=======================
Installation via Docker
=======================

We provide prebuilt Docker Images on `GitHub <https://github.com/kryptoloesungen/CiVerLy/releases/latest/>`_.
Of course, you need `Docker <https://www.docker.com/>`_ to run a Docker image.
To do so, download the image and then run:

.. code-block:: console

   $ wget https://github.com/kryptoloesungen/CiVerLy/releases/latest/download/civerly-docker.tar.gz
   $ docker load < civerly-docker.tar.gz:<version>

Then, to start the container run:

.. code-block:: console

   $ docker run -it civerly

This will drop you into a shell with CiVerLy and it dependencies available.

