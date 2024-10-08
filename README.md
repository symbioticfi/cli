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
  --provider TEXT  Ethereum provider URL [http(s)]
  --help           Show this message and exit.

Commands:
  isnet         Check if address is network
  isop          Check if address is operator
  middleware    Get network middleware address
  netops        List all operators opted in network
  nets          List all networks
  netstakes     Show stakes of all operators in network
  opnets        List all networks where operator is opted in
  ops           List all operators
  opstakes      Show operator stakes in all networks
  vaultnets     List all networks associated with the given vault.
  vaultnetsops  List all operators and their associated networks for the...
  vaultops      List all operators opted into the given vault.
  vaults        List all vaults
```
