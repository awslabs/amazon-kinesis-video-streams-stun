# Unit Tests for amazon-kinesis-video-streams-stun library

This directory contains unit tests for amazon-kinesis-video-streams-stun library.
It submodules the [CMock](https://github.com/ThrowTheSwitch/CMock) framework
(which submodules [Unity](https://github.com/throwtheswitch/unity/)).

## Getting Started

### Prerequisites

You can run these tests on any GNU Make compatible system. To build and run
these tests, you must have the following:

1. Make (You can check whether you have this by typing `make --version`).
   - Not found? Try `apt-get install make`.
1. Ruby (You can check whether you have this by typing `ruby --version`).
   - Not found? Try `apt-get install ruby`.
1. CMake version > 3.13.0 (You can check whether you have this by typing
   `cmake --version`).
   - Not found? Try `apt-get install cmake`.
   - Run the `cmake --version` command. If still the version number is >=
     3.13.0, skip to (4.) or else, continue.
   - You will need to get the latest CMake version using curl or wget (or
     similar command).
     - Uninstall the current version of CMake using
       `sudo apt remove --purge --auto-remove cmake`.
     - Download the [CMAKE version 3.13.0](https://cmake.org/files/v3.13/).
     - Extract the cmake download using `tar -xzvf cmake-3.13.0.tar.gz`.
     - Go to the extracted folder (`cd cmake-3.13.0`) and run `./bootstrap`.
     - Run `make -j$(nproc)` and then run `sudo make install`.
     - Check the version using `cmake --version` command.
1. lcov version 1.14 (You can check whether you have this by typing
   `lcov --version`).
     - Not found? Try `sudo apt-get install lcov`

### To run the Unit tests:

Go to the root directory of the amazon-kinesis-video-streams-stun repo and run
the following script:

```sh
#!/bin/bash
# This script should be run from the root directory of the amazon-kinesis-video-streams-stun
 repo.

if [[ ! -d source ]]; then
    echo "Please run this script from the root directory of the amazon-kinesis-video-streams-stun
     repo."
    exit 1
fi

UNIT_TEST_DIR="test/unit-test"
BUILD_DIR="${UNIT_TEST_DIR}/build"

# Create the build directory using CMake:
rm -rf ${BUILD_DIR}/
cmake -S ${UNIT_TEST_DIR} -B ${BUILD_DIR}/ -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Debug -DBUILD_CLONE_SUBMODULES=ON -DCMAKE_C_FLAGS='--coverage -Wall -Wextra -Werror -DNDEBUG -DLIBRARY_LOG_LEVEL=LOG_DEBUG'

# Create the executables:
make -C ${BUILD_DIR}/ all

pushd ${BUILD_DIR}/
# Run the tests for all units
ctest -E system --output-on-failure
popd

# Calculate the coverage
make -C ${BUILD_DIR}/ coverage
```

You should see an output similar to this:

```
test_H264_Packetizer_AddNalu             PASS
test_H264_Packetizer_AddFrame            PASS

=================== SUMMARY =====================

Tests Passed  : 16
Tests Failed  : 0
Tests Ignored : 0
```
