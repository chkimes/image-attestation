#!/bin/bash

echo GENERATE VM INSTANCE LAUNCH ATTESTATION

attestor -e examples/attest.json -o examples/launch.in-toto.json --pretty-print examples/vm.id