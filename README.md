# Tests for PWN Protocol
This repository serves as an example of tests written in a development and testing framework called [Wake](https://github.com/Ackee-Blockchain/wake).

![horizontal splitter](https://github.com/Ackee-Blockchain/wake-detect-action/assets/56036748/ec488c85-2f7f-4433-ae58-3d50698a47de)

## Setup

1. Clone this repository
2. `git submodule update --init --recursive` if not cloned with `--recursive`

## Running fuzz tests

1. `wake up pytypes` to generate pytypes
2. `wake test` to run proof-of-concept scripts for discovered critical vulnerabilities and fuzz tests

Requires `wake` version `4.14.0` or later.
Tested with `anvil` version `anvil 0.2.0 (c13d42e 2024-11-19T00:22:29.641484000Z)`. Fuzz tests expect a local Ethereum mainnet node running at http://localhost:8545.