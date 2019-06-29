FROM buildpack-deps:stretch

ARG ISPC_HOME=/usr/local/src/ispc
ARG LLVM_HOME=/usr/local/src/llvm
ARG LLVM_VERSION=8.0

ENV PATH=$LLVM_HOME/bin-$LLVM_VERSION/bin:$ISPC_HOME/bin/bin:$PATH

RUN set -x \
 && apt-get update \
 && apt purge -y --auto-remove cmake \
 && apt-get install -y bison flex \
 && wget https://cmake.org/files/v3.8/cmake-3.8.0-Linux-x86_64.sh \
 && mkdir /opt/cmake \
 && sh cmake-3.8.0-Linux-x86_64.sh --prefix=/opt/cmake --skip-license \
 && ln -s /opt/cmake/bin/cmake /usr/local/bin/cmake \
 && rm cmake-3.8.0-Linux-x86_64.sh \
 && cmake --version \
 && git clone git://github.com/ispc/ispc.git $ISPC_HOME \
 && cd $ISPC_HOME \
 && python alloy.py -b --version=$LLVM_VERSION --git --selfbuild \
 && rm -rf $LLVM_HOME/build-$LLVM_VERSION $LLVM_HOME/llvm-$LLVM_VERSION $LLVM_HOME/bin-$LLVM_VERSION_temp $LLVM_HOME/build-$LLVM_VERSION_temp \
 && mkdir build \
 && cd build \
 && echo $PATH \
 && ls -la /usr/local/src/llvm/bin-8.0/bin \
 && cmake -DCMAKE_INSTALL_PREFIX=$ISPC_HOME/bin -DCMAKE_CXX_COMPILER=clang++ $ISPC_HOME \
 && make -j$(nproc) \
 && make install \
 && cd .. \
 && rm -rf build \
 && mv $LLVM_HOME/bin-$LLVM_VERSION / \
 && rm -rf $LLVM_HOME \
 && mkdir -p $LLVM_HOME \
 && mv /bin-$LLVM_VERSION $LLVM_HOME \
 && cd / \
 && mv $ISPC_HOME/bin /ispcbin \
 && rm -rf $ISPC_HOME \
 && mkdir $ISPC_HOME \
 && mv /ispcbin $ISPC_HOME/bin \
 && ispc --version
