============================
Installation of Dependencies
============================

Install SageMath
================
We install sage in Version 10.4.
First, install all the prerequisites, build tools and LATEX related tools for
sage.
For Debian/Ubuntu, install those by running the following commands.
For other Linux systems, consult the `sage installation manual <https://doc.sagemath.org/html/en/installation/source.html#linux-system-package-installation>`_.

.. code-block:: console

   $ sudo apt-get install bc binutils bzip2 ca-certificates cliquer cmake curl \
                ecl eclib-tools fflas-ffpack g++ gap gcc gengetopt gfan gfortran \
                glpk-utils gmp-ecm lcalc libatomic-ops-dev libboost-dev \
                libbraiding-dev libbrial-dev libbrial-groebner-dev libbz2-dev \
                libcdd-dev libcdd-tools libcliquer-dev libcurl4-openssl-dev libec-dev \
                libecm-dev libffi-dev libflint-dev libfplll-dev libfreetype-dev \
                libgap-dev libgc-dev libgd-dev libgf2x-dev libgiac-dev libgivaro-dev \
                libglpk-dev libgmp-dev libgsl-dev libhomfly-dev libiml-dev \
                liblfunction-dev liblinbox-dev liblrcalc-dev liblzma-dev libm4ri-dev \
                libm4rie-dev libmpc-dev libmpfi-dev libmpfr-dev libncurses5-dev \
                libntl-dev libopenblas-dev libpari-dev libplanarity-dev libppl-dev \
                libprimesieve-dev libpython3-dev libqhull-dev libreadline-dev \
                librw-dev libsingular4-dev libsqlite3-dev libssl-dev \
                libsuitesparse-dev libsymmetrica2-dev libz-dev libzmq3-dev m4 make \
                maxima maxima-sage meson nauty ninja-build openssl palp pari-doc \
                pari-elldata pari-galdata pari-galpol pari-gp2c pari-seadata patch \
                patchelf perl pkg-config planarity ppl-dev python3 python3-setuptools \
                python3-venv singular singular-doc sqlite3 sympow tachyon tar texinfo \
                tox xcas xz-utils
   $ sudo apt-get install autoconf automake gh git gpgconf libtool \
                openssh-client pkg-config
   $ sudo apt-get install default-jdk dvipng ffmpeg fonts-freefont-otf \
                imagemagick latexmk libavdevice-dev libjpeg-dev pandoc tex-gyre \
                texlive-fonts-recommended texlive-lang-cyrillic texlive-lang-english \
                texlive-lang-european texlive-lang-french texlive-lang-german \
                texlive-lang-italian texlive-lang-japanese texlive-lang-polish \
                texlive-lang-portuguese texlive-lang-spanish texlive-latex-extra \
                texlive-luatex texlive-xetex xindy

Next, obtain the sources for sage by running the following commands:

.. code-block:: console

   $ cd ~
   $ git clone --origin upstream https://github.com/sagemath/sage.git
   $ cd sage
   $ git checkout 10.4

Now, build sage by running the following commands:

.. code-block:: console

   $ make configure
   $ export MAKE="make -j4"
   $ ./configure --with-system-python3=no
   $ make

.. note::
   The command ``export MAKE="make -j4"`` instructs the build process to run
   four jobs in parallel.
   If your CPU is sufficiently strong, you might be able to speed up the build
   process by increasing this number, e.g., to eight or even 16.
   On the other hand, if the build process fails, try to run again without this command.

Finally, make sage available globally:

.. code-block:: console

   $ sudo ln -s $PWD/sage /usr/local/bin/sage

Start sage (and then exit it again) to verify that the correct version is installed:

.. code-block:: console

   $ sage
   +--------------------------------------------------------------------+
   | SageMath version 10.4, Release Date: 2024-07-19                    |
   | Using Python 3.12.4. Type "help()" for help.                       |
   +--------------------------------------------------------------------+
   sage: exit()

Install GLPK
============

We use GLPK, the GNU Linear Programming Kit, as MILP solver.
To install GLPK (Version 5.0), first download the sources by running the following commands:

.. code-block:: console

   $ cd ~
   $ wget https://ftp.gnu.org/gnu/glpk/glpk-5.0.tar.gz
   $ tar -vxf glpk-5.0.tar.gz

Then, install GLPK by running the following commands:

.. code-block:: console

   $ cd glpk-5.0
   $ ./configure
   $ make
   $ sudo make install


Install SCIP
============

SCIP is another MILP solver.
Run the following commands to install SCIP (Version 9.1.0).
Notice that soplex is not available in the package repository of Ubuntu 22.04 (it is for Ubuntu 24.04).
If your system is connected to the internet, soplex will be downloaded and installed automatically during the installation of SCIP.

.. code-block:: console

   $ sudo apt-get install wget cmake g++ m4 xz-utils libgmp-dev unzip zlib1g-dev \
                libboost-program-options-dev libboost-serialization-dev \
                libboost-regex-dev libboost-iostreams-dev libtbb-dev libreadline-dev \
                pkg-config git liblapack-dev libgsl-dev flex bison libcliquer-dev \
                gfortran file dpkg-dev libopenblas-dev rpm soplex libsoplex-dev
   $ cd ~
   $ git clone https://github.com/scipopt/scip.git
   $ cd scip
   $ git checkout v910
   $ mkdir build
   $ cd build
   $ cmake .. -DPAPILO=off -DZIMPL=off -DIPOPT=off
   $ make
   $ make check
   $ sudo make install


Install Gurobi
==============
Gurobi is commercial MILP solver.
That is, a licence is required to use it.
Here, we assume that you have already setup an account on
https://www.gurobi.com/ and already have obtained a licence there.

To install Gurobi (Version 11.0.3), go to https://www.gurobi.com/downloads/gurobi-software/
and download the archive for x64 Linux.
We assume that the archive is stored in the ``~/Downloads`` directory.
Run the following commands:

.. code-block:: console

   $ cd ~
   $ mv ~/Downloads/gurobi11.0.3_linux64.tar.gz .
   $ tar -xzf gurobi11.0.3_linux64.tar.gz
   $ rm gurobi11.0.3_linux64.tar.gz

In the following, we assume that the used shell is bash.
Verify this by running

.. code-block:: console

   $ echo $0

If the result is not bash, adapt the following commands accordingly.
To make the Gurobi executables available globally, we have to add some lines to the ``.bashrc`` file.

.. code-block:: console

   $ echo ’# Make Gurobi files available globally’ >> ~/.bashrc
   $ echo ’export GUROBI_HOME=~/gurobi1103/linux64/’ >> ~/.bashrc
   $ echo ’export PATH="$GUROBI_HOME/bin:$PATH"’ >> ~/.bashrc
   $ echo ’export LD_LIBRARY_PATH="${GUROBI_HOME}/lib"’ >> ~/.bashrc
   $ source ~/.bashrc

Finally, goto to https://portal.gurobi.com/iam/licenses/list which should list
your licence.
On the right-hand side, click the icon with a monitor and a downward facing
arrow (next to the bell).
This will show you a command of the following form:

.. code-block:: console

   $ grbgetkey xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

Copy it and execute it on your machine.

Install CryptoMiniSat
=====================
We use CryptoMiniSat (Version 5.11.21) as SAT solver.
We recommend installing CryptoMiniSat from source.
For this, we follow the instructions in the Compiling in Linux section on the
`CryptoMiniSat GitHub page <https://github.com/msoos/cryptominisat?tab=readme-ov-file#compiling-in-linux>`_.
First, if not yet installed, we need to install some build tools.
On Debian/Ubuntu run the following command:

.. code-block:: console

   $ sudo apt-get install build-essential cmake

Next, install cadical using the following commands:

.. code-block:: console

   $ cd ~
   $ git clone https://github.com/meelgroup/cadical
   $ cd cadical
   $ git checkout mate-only-libraries-1.8.0
   $ ./configure
   $ make
   $ cd ..

Now, install cadiback using the following commands:

.. code-block:: console

   $ git clone https://github.com/meelgroup/cadiback
   $ cd cadiback
   $ git checkout mate
   $ ./configure
   $ make
   $ cd ..

Finally, install CryptoMiniSat:

.. code-block:: console

   $ git clone https://github.com/msoos/cryptominisat.git
   $ cd cryptominisat
   $ git checkout 5.11.21
   $ mkdir build && cd build
   $ cmake ..
   $ make
   $ sudo make install
   $ sudo ldconfig

Install Cadical
===============
Cadical is another SAT solver.
To install Cadical (Version 2.0.0), run the following commands.

.. code-block:: console

   $ cd ~
   $ git clone https://github.com/arminbiere/cadical cadical-standalone
   $ cd cadical-standalone
   $ git checkout rel-2.0.0
   $ ./configure
   $ make

Finally, make Cadical available globally:

.. code-block:: console

   $ sudo ln -s $PWD/build/cadical /usr/local/bin/cadical


Install Espresso
================
Espresso is a logic minimizer.
To install Espresso (Version 2.3), run the following commands.

.. code-block:: console

   $ cd ~
   $ git clone https://github.com/classabbyamp/espresso-logic.git
   $ cd espresso-logic
   $ git checkout 1.1
   $ cd espresso-src
   $ make

Finally, make Espresso available globally:

.. code-block:: console

   $ cd ../bin
   $ sudo ln -s $PWD/espresso /usr/local/bin/espresso
