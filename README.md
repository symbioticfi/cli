# Symbiotic CLI (symb)

Simple CLI tool for fetching data and interacting with Symbiotic core smart contracts.

## Documentation

Can be found [here](https://docs.symbiotic.fi/guides/cli).

## Install

```bash
pip3 install -r requirements.txt
```

## Usage

```
$ python3 symb.py
Usage: symb.py [GENERAL_OPTIONS] COMMAND [ARGS] [OPTIONS]

General options:
  --help                       Show all the possible commands and exit.
  --chain                TEXT  Chain ID to use.
  --provider             TEXT  Ethereum provider URL [http(s)].

Commands:
  --- for general use (related to Networks) ---

  isnet                        Check if address is network.
  middleware                   Get network middleware address.
  nets                         List all networks.
  netops                       List all operators opted in network.
  netstakes                    Show stakes of all operators in network.
  pending-resolver             Get a current resolver for a subnetwork in a vault.
  resolver                     Get a pending resolver for a subnetwork in a vault.

  --- for general use (related to Operators) ---

  isop                         Check if address is operator.
  ops                          List all operators.
  opnets                       List all networks where operator is opted in.
  op-vault-net-stake           Get operator stake in vault for network (includes data about the operator's shares if NetworkRestakeDelegator).
  opstakes                     Show operator stakes in all networks.
  check-opt-in-network         Check if operator is opted in to a network.
  check-opt-in-vault           Check if is opted in to a vault.

  --- for general use (related to Vaults) ---

  isvault                      Check if address is vault.
  vaults                       List all vaults.
  vaultnets                    List all networks associated with the given vault.
  vaultops                     List all operators opted into the given vault.
  vaultnetsops                 List all operators and their associated networks for the given vault.

  --- for general use (related to Stakers) ---

  active-balance-of            Get an active balance of a given account at a particular vault.
  withdrawals-of               Get some epoch's withdrawals of a given account at a particular vault.
  withdrawals-claimed          Check if some epoch's withdrawals of a given account at a particular vault are claimed.

  --- for Networks ---

  register-network             Register the signer as a network.
  set-max-network-limit        Set a maximum network limit at the vault's delegator.
  set-resolver                 Set a resolver for a subnetwork at VetoSlasher.

  --- for Operators ---

  register-operator            Register the signer as an operator.
  opt-in-network               Opt-in to a network.
  opt-in-network-signature     Get a signature for opt-in to a network.
  opt-in-vault                 Opt-in to a vault.
  opt-in-vault-signature       Get a signature for opt-in to a vault.
  opt-out-network              Opt-out from a network.
  opt-out-network-signature    Get a signature for opt-out from a network.
  opt-out-vault                Opt-out from a vault.
  opt-out-vault-signature      Get a signature for opt-out from a vault.

  --- for Vault Curators ---

  set-network-limit            Set a network limit at the vault's delegator.
  set-operator-network-limit   Set an operator-network limit at the vault's delegator.
  set-operator-network-shares  Set an operator-network shares at the vault's delegator.

  --- for Stakers ---

  deposit                      Deposit to the vault.
  withdraw                     Withdraw from the vault.
  claim                        Claim a withdrawal for some epoch at the vault.


Options:
  --help                       Show the command's description and exit.
  --private-key           TEXT Private key to sign transactions with (only for write functionality).
  --ledger                     Flag to use a ledger to sign transactions (only for write functionality).
  --ledger-address        TEXT Address of the ledger's account to use to sign transactions (only for write functionality).
```
