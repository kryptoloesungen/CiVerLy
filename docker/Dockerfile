FROM sagemath/sagemath:10.4

USER root

COPY ./ /home/civerly/

RUN ln -fs /usr/share/zoneinfo/Europe/Berlin /etc/localtime
RUN sudo apt-get update && sudo apt-get install -y build-essential wget texlive-full

# Install GLPK
RUN sudo apt-get install -y wget
WORKDIR /home/
RUN wget https://ftp.gnu.org/gnu/glpk/glpk-5.0.tar.gz
RUN tar -vxf glpk-5.0.tar.gz
WORKDIR /home/glpk-5.0
RUN ./configure
RUN make
RUN sudo make install

# Install SCIP
RUN sudo apt-get install -y wget cmake g++ m4 xz-utils libgmp-dev unzip zlib1g-dev \
             libboost-program-options-dev libboost-serialization-dev \
             libboost-regex-dev libboost-iostreams-dev libtbb-dev libreadline-dev \
             pkg-config git liblapack-dev libgsl-dev flex bison libcliquer-dev \
             gfortran file dpkg-dev libopenblas-dev rpm
WORKDIR /home/
RUN git clone https://github.com/scipopt/scip.git
WORKDIR /home/scip
RUN git checkout v910
RUN mkdir build
WORKDIR /home/scip/build
RUN cmake .. -DPAPILO=off -DZIMPL=off -DIPOPT=off
RUN make
RUN make check
RUN sudo make install

# Install Cryptominisat
RUN sudo apt-get install -y build-essential cmake
WORKDIR /home/
RUN git clone https://github.com/meelgroup/cadical
WORKDIR /home/cadical
RUN git checkout mate-only-libraries-1.8.0
RUN ./configure
RUN make
WORKDIR /home/
RUN git clone https://github.com/meelgroup/cadiback
WORKDIR /home/cadiback
RUN git checkout mate
RUN ./configure
RUN make
WORKDIR /home/
RUN git clone https://github.com/msoos/cryptominisat.git
WORKDIR /home/cryptominisat
RUN git checkout 5.11.21
RUN mkdir build
WORKDIR /home/cryptominisat/build
RUN cmake ..
RUN make
RUN sudo make install
RUN sudo ldconfig

# Install Cadical
WORKDIR /home/
RUN git clone https://github.com/arminbiere/cadical cadical-standalone
WORKDIR /home/cadical-standalone
RUN git checkout rel-2.0.0
RUN ./configure
RUN make
RUN sudo ln -s $PWD/build/cadical /usr/local/bin/cadical

# Install Espresso
WORKDIR /home/
RUN git clone https://github.com/classabbyamp/espresso-logic.git
WORKDIR /home/espresso-logic
RUN git checkout 1.1
WORKDIR /home/espresso-logic/espresso-src
RUN make
WORKDIR /home/espresso-logic/bin
RUN sudo ln -s $PWD/espresso /usr/local/bin/espresso

# install CiVerLy
WORKDIR /home/civerly/
RUN make
RUN sage --python -m pip install --no-index --no-build-isolation .

