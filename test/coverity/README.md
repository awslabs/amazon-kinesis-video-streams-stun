# Static code analysis for STUN Library
This directory is made for the purpose of statically analyzing the STUN Library using
[Black Duck Coverity](https://www.blackduck.com/static-analysis-tools-sast/coverity.html) static analysis tool.
This configuration focuses on detecting code defects such as memory leaks, null pointer dereferences,
buffer overflows, and other code quality issues.

> **Note**
For generating the report as outlined below, we have used Coverity version 2025.6.0.

## Getting Started
### Prerequisites
You can run this on a platform supported by Coverity. The list of supported platforms and other details can be found [here](https://documentation.blackduck.com/bundle/coverity-docs/page/deploy-install-guide/topics/supported_platforms_for_coverity_analysis.html).
To compile and run the Coverity target successfully, you must have the following:

1. CMake version > 3.13.0 (You can check whether you have this by typing `cmake --version`).
2. GCC compiler
    - You can see the download and installation instructions [here](https://gcc.gnu.org/install/).
3. Download the repo including the submodules using the following commands:
    - `git clone --recurse-submodules https://github.com/awslabs/amazon-kinesis-video-streams-stun`
    - `cd ./amazon-kinesis-video-streams-stun`

### To build and run coverity:
Go to the root directory of the library and run the following commands:
~~~
cmake -S test/coverity/ -B build
cmake --build build --target coverity_scan
~~~

These commands will:
1. Configure the build system using the Coverity-specific CMake configuration.
2. Build and execute the Coverity scan target, which handles all the necessary steps including:
   - Compiler configuration.
   - Static analysis execution.
   - Report generation in both HTML and JSON formats.

You should now have the HTML formatted violations list in a directory named `build/coverity_report`.
