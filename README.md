# Symbiotic CLI (symb)

Simple CLI tool for fetching data from symbiotic core smart contracts.

## Install

```bash
pip3 install -r requirements.txt
```

## Usage

```
$ python3 symb.py
Usage: symb.py [OPTIONS] COMMAND [ARGS]...

Options:
  --provider        TEXT  Ethereum provider URL [http(s)]
  --help                  Show this message and exit.
  --private-key     TEXT  Private key to sign transactions with (only for write functionality).
  --ledger                Flag if to use a ledger to sign transactions (only for write functionality). Make sure to install Ledger Live, open the Ethereum app, and enable the blind signing first.
  --ledger-address  TEXT  Address of the ledger's account to use to sign transactions (only for write functionality).


Commands:
  isnet                        Check if address is network
  isop                         Check if address is operator
  middleware                   Get network middleware address
  netops                       List all operators opted in network
  nets                         List all networks
  netstakes                    Show stakes of all operators in network
  opnets                       List all networks where operator is opted in
  ops                          List all operators
  opstakes                     Show operator stakes in all networks
  vaultnets                    List all networks associated with the given vault.
  vaultnetsops                 List all operators and their associated networks for the...
  vaultops                     List all operators opted into the given vault.
  vaults                       List all vaults
  set-max-network-limit        Set a maximum network limit (called by the network) at the given vault's delegator.
  set-network-limit            Set a network limit (called by the vault curator) at the given vault's delegator.
  set-operator-network-limit   Set an operator-network limit (called by the vault curator) at the given vault's FullRestakeDelegator.
  set-operator-network-shares  Set an operator-network limit (called by the vault curator) at the given vault's NetworkRestakeDelegator.
```
