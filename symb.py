import warnings

warnings.filterwarnings("ignore", category=UserWarning, module="eth_utils")

import click
from web3 import Web3
from w3multicall.multicall import W3Multicall
import ledgereth
from ledgereth.messages import sign_typed_data_draft
from eth_account import Account
from eth_account.messages import encode_typed_data
from datetime import datetime
from time import time
import re
from decimal import Decimal, InvalidOperation
import json
import os
from eth_abi import abi


class AddressType(click.ParamType):
    name = "ethereum_address"
    pattern = re.compile(r"^0x[0-9a-fA-F]{40}$")

    def convert(self, value, param, ctx):
        if self.pattern.match(value):
            return value
        else:
            self.fail(f"{value} is not a valid address", param, ctx)


class Bytes32Type(click.ParamType):
    name = "bytes32"

    def convert(self, value, param, ctx):
        if isinstance(value, bytes):
            if len(value) == 32:
                return value
            else:
                self.fail(f"{value} is not 32 bytes", param, ctx)
        elif isinstance(value, str):
            if value.startswith("0x"):
                value = value[2:]
            if len(value) != 64 or not re.fullmatch(r"[0-9a-fA-F]{64}", value):
                self.fail(f"{value} is not a valid bytes32 hex string", param, ctx)
            try:
                return bytes.fromhex(value)
            except ValueError:
                self.fail(f"{value} is not a valid hex string", param, ctx)
        else:
            self.fail(f"Invalid input: {value}", param, ctx)


class Uint256Type(click.ParamType):
    name = "uint256"

    def convert(self, value, param, ctx):
        try:
            ivalue = int(value)
            if 0 <= ivalue <= 2**256 - 1:
                return ivalue
            else:
                self.fail(
                    f"{value} is not a valid uint256 (must be between 0 and 2^256 - 1)",
                    param,
                    ctx,
                )
        except ValueError:
            self.fail(f"{value} is not a valid integer", param, ctx)


class Uint96Type(click.ParamType):
    name = "uint96"

    def convert(self, value, param, ctx):
        try:
            ivalue = int(value)
            if 0 <= ivalue <= 2**96 - 1:
                return ivalue
            else:
                self.fail(
                    f"{value} is not a valid uint96 (must be between 0 and 2^96 - 1)",
                    param,
                    ctx,
                )
        except ValueError:
            self.fail(f"{value} is not a valid integer", param, ctx)


class Uint48Type(click.ParamType):
    name = "uint48"

    def convert(self, value, param, ctx):
        try:
            ivalue = int(value)
            if 0 <= ivalue <= 2**48 - 1:
                return ivalue
            else:
                self.fail(
                    f"{value} is not a valid uint48 (must be between 0 and 2^48 - 1)",
                    param,
                    ctx,
                )
        except ValueError:
            self.fail(f"{value} is not a valid integer", param, ctx)


class TokenAmountType(click.ParamType):
    name = "token_amount"

    def __init__(self, decimals=18):
        self.decimals = decimals

    def convert(self, value, param, ctx):
        try:
            # Convert the string input to a Decimal
            amount = Decimal(value)
        except InvalidOperation:
            self.fail(f"Invalid token amount: {value}", param, ctx)

        # Check for negative amounts
        if amount < 0:
            self.fail(f"Token amount cannot be negative: {value}", param, ctx)

        if amount == 0:
            self.fail(f"Token amount should not be zero", param, ctx)

        if amount >= 2**256:
            self.fail(f"Token amount is too large: {value}", param, ctx)

        return amount


class ChainType(click.ParamType):
    name = "chain"

    CHAIN_IDS = {
        "holesky": "holesky",
        "17000": "holesky",
        "sepolia": "sepolia",
        "11155111": "sepolia",
        "mainnet": "mainnet",
        "1": "mainnet",
        "hoodi": "hoodi",
        "560048": "hoodi",
    }

    def convert(self, value, param, ctx):
        value_str = str(value).lower()
        if value_str in self.CHAIN_IDS:
            return self.CHAIN_IDS[value_str]
        else:
            self.fail(
                f'Invalid chain: {value}. Valid options are: {", ".join(self.CHAIN_IDS.keys())}',
                param,
                ctx,
            )


address_type = AddressType()
bytes32_type = Bytes32Type()
uint256_type = Uint256Type()
uint96_type = Uint96Type()
uint48_type = Uint48Type()
token_amount_type = TokenAmountType()
chain_type = ChainType()


def load_abi(abis_path, name):
    return open(f"{abis_path}/{name}ABI.json", "r").read()


class SymbioticCLI:

    CHAIN_IDS = {
        "holesky": 17000,
        "sepolia": 11155111,
        "mainnet": 1,
        "hoodi": 560048,
    }

    PROVIDERS = {
        "holesky": "https://ethereum-holesky-rpc.publicnode.com",
        "sepolia": "https://ethereum-sepolia-rpc.publicnode.com",
        "mainnet": "https://ethereum-rpc.publicnode.com",
        "hoodi": "https://ethereum-hoodi-rpc.publicnode.com",
    }

    ABIS_PATH = "./abi"

    ABIS = {
        "op_registry": load_abi(ABIS_PATH, "OperatorRegistry"),
        "net_registry": load_abi(ABIS_PATH, "NetworkRegistry"),
        "op_vault_opt_in": load_abi(ABIS_PATH, "OperatorVaultOptInService"),
        "op_net_opt_in": load_abi(ABIS_PATH, "OperatorNetworkOptInService"),
        "middleware_service": load_abi(ABIS_PATH, "NetworkMiddlewareService"),
        "vault_factory": load_abi(ABIS_PATH, "VaultFactory"),
        "entity": load_abi(ABIS_PATH, "NetworkRestakeDelegator"),
        "delegator": load_abi(ABIS_PATH, "NetworkRestakeDelegator"),
        "network_restake_delegator": load_abi(ABIS_PATH, "NetworkRestakeDelegator"),
        "full_restake_delegator": load_abi(ABIS_PATH, "FullRestakeDelegator"),
        "operator_specific_delegator": load_abi(ABIS_PATH, "OperatorSpecificDelegator"),
        "operator_network_specific_delegator": load_abi(
            ABIS_PATH, "OperatorNetworkSpecificDelegator"
        ),
        "veto_slasher": load_abi(ABIS_PATH, "VetoSlasher"),
        "vault": load_abi(ABIS_PATH, "Vault"),
        "erc20": load_abi(ABIS_PATH, "VaultTokenized"),
    }

    ADDRESSES = {
        "holesky": {
            "op_registry": "0x6F75a4ffF97326A00e52662d82EA4FdE86a2C548",
            "net_registry": "0x7d03b7343BF8d5cEC7C0C27ecE084a20113D15C9",
            "op_vault_opt_in": "0x95CC0a052ae33941877c9619835A233D21D57351",
            "op_net_opt_in": "0x58973d16FFA900D11fC22e5e2B6840d9f7e13401",
            "middleware_service": "0x62a1ddfD86b4c1636759d9286D3A0EC722D086e3",
            "vault_factory": "0x407A039D94948484D356eFB765b3c74382A050B4",
        },
        "sepolia": {
            "op_registry": "0x6F75a4ffF97326A00e52662d82EA4FdE86a2C548",
            "net_registry": "0x7d03b7343BF8d5cEC7C0C27ecE084a20113D15C9",
            "op_vault_opt_in": "0x95CC0a052ae33941877c9619835A233D21D57351",
            "op_net_opt_in": "0x58973d16FFA900D11fC22e5e2B6840d9f7e13401",
            "middleware_service": "0x62a1ddfD86b4c1636759d9286D3A0EC722D086e3",
            "vault_factory": "0x407A039D94948484D356eFB765b3c74382A050B4",
        },
        "mainnet": {
            "op_registry": "0xAd817a6Bc954F678451A71363f04150FDD81Af9F",
            "net_registry": "0xC773b1011461e7314CF05f97d95aa8e92C1Fd8aA",
            "op_vault_opt_in": "0xb361894bC06cbBA7Ea8098BF0e32EB1906A5F891",
            "op_net_opt_in": "0x7133415b33B438843D581013f98A08704316633c",
            "middleware_service": "0xD7dC9B366c027743D90761F71858BCa83C6899Ad",
            "vault_factory": "0xAEb6bdd95c502390db8f52c8909F703E9Af6a346",
        },
        "hoodi": {
            "op_registry": "0x6F75a4ffF97326A00e52662d82EA4FdE86a2C548",
            "net_registry": "0x7d03b7343BF8d5cEC7C0C27ecE084a20113D15C9",
            "op_vault_opt_in": "0x95CC0a052ae33941877c9619835A233D21D57351",
            "op_net_opt_in": "0x58973d16FFA900D11fC22e5e2B6840d9f7e13401",
            "middleware_service": "0x62a1ddfD86b4c1636759d9286D3A0EC722D086e3",
            "vault_factory": "0x407A039D94948484D356eFB765b3c74382A050B4",
        },
    }

    DELEGATOR_TYPES_ENTITIES = {
        0: "network_restake_delegator",
        1: "full_restake_delegator",
        2: "operator_specific_delegator",
        3: "operator_network_specific_delegator",
    }

    DELEGATOR_TYPES_NAMES = {
        0: "NetworkRestake",
        1: "FullRestake",
        2: "OperatorSpecific",
        3: "OperatorNetworkSpecific",
    }

    SLASHER_TYPES_NAMES = {
        -1: "NonSlashable",
        0: "InstantSlasher",
        1: "VetoSlasher",
    }

    SUBNETWORKS = [0, 1]  # TODO: Generalize subnetworks

    def __init__(self, chain, provider):
        self.chain = chain
        self.provider = provider if provider else self.PROVIDERS[self.chain]
        self.w3 = Web3(Web3.HTTPProvider(self.provider))

        if self.w3.eth.chain_id != self.CHAIN_IDS[self.chain]:
            raise ValueError(
                f"Mismatch between specified chain ID ({self.CHAIN_IDS[self.chain]}) and provider's chain ID ({self.w3.eth.chain_id})"
            )

        self.addresses = {
            key: self.normalize_address(address)
            for key, address in self.ADDRESSES[self.chain].items()
        }
        self.contracts = {}
        self._cache = {"token_meta": {}}
        self.init_contracts()

        self._error_selectors = {}
        self.build_error_selector_map()

        print(f"Connected to chain ID {self.w3.eth.chain_id}")

    def init_contracts(self):
        for name, address in self.addresses.items():
            self.contracts[name] = self.w3.eth.contract(
                address=address, abi=self.ABIS[name]
            )

    def build_error_selector_map(self):
        for abi_name in os.listdir(self.ABIS_PATH):
            parsed_abi = json.loads(open(f"{self.ABIS_PATH}/{abi_name}", "r").read())
            for item in parsed_abi:
                if item.get("type") == "error":
                    error_name = item["name"]
                    if len(item["inputs"]) == 0:
                        input_types = []
                        type_sig = f"{error_name}()"
                    else:
                        input_types = [inp["type"] for inp in item["inputs"]]
                        type_sig = f"{error_name}({','.join(input_types)})"

                    selector = Web3.keccak(text=type_sig)[:4].hex()

                    self._error_selectors[selector] = (error_name, input_types)

    def normalize_address(self, address):
        return Web3.to_checksum_address(address)

    def get_subnetwork(self, net, subnet_id=0):
        net = self.normalize_address(net)
        return f"{net}{hex(subnet_id)[2:].rjust(24, '0')}"

    def get_token_meta(self, token):
        token = self.normalize_address(token)

        if token in self._cache["token_meta"]:
            return self._cache["token_meta"][token]
        w3_multicall = W3Multicall(self.w3)
        w3_multicall.add(W3Multicall.Call(token, "symbol()(string)"))
        w3_multicall.add(W3Multicall.Call(token, "decimals()(uint8)"))
        try:
            res = w3_multicall.call()
        except:
            res = [None, None]
        if not res[0] or not res[1]:
            meta = {"symbol": "Unknown", "decimals": 0}
        else:
            meta = {"symbol": res[0], "decimals": int(res[1])}
        self._cache["token_meta"][token] = meta
        return meta

    def get_middleware(self, net):
        net = self.normalize_address(net)
        return self.normalize_address(
            (self.contracts["middleware_service"].functions.middleware(net).call())
        )

    def get_collateral(self, vault_address):
        vault_address = self.normalize_address(vault_address)
        return self.normalize_address(
            self.get_data("vault", vault_address, "collateral")
        )

    def get_delegator(self, vault_address):
        vault_address = self.normalize_address(vault_address)
        return self.normalize_address(
            self.get_data("vault", vault_address, "delegator")
        )

    def get_slasher(self, vault_address):
        vault_address = self.normalize_address(vault_address)
        return self.normalize_address(self.get_data("vault", vault_address, "slasher"))

    def get_nets(self):
        total_entities = self.contracts["net_registry"].functions.totalEntities().call()
        w3_multicall = W3Multicall(self.w3)
        for i in range(total_entities):
            w3_multicall.add(
                W3Multicall.Call(
                    self.addresses["net_registry"], "entity(uint256)(address)", i
                )
            )
        nets = w3_multicall.call()
        nets = [self.normalize_address(net) for net in nets]
        w3_multicall = W3Multicall(self.w3)
        for net in nets:
            w3_multicall.add(
                W3Multicall.Call(
                    self.addresses["middleware_service"],
                    "middleware(address)(address)",
                    net,
                )
            )
        middlewares = w3_multicall.call()
        middlewares = [self.normalize_address(middleware) for middleware in middlewares]
        return [
            {"net": net, "middleware": middleware}
            for net, middleware in zip(nets, middlewares)
        ]

    def get_ops(self):
        total_entities = self.contracts["op_registry"].functions.totalEntities().call()
        w3_multicall = W3Multicall(self.w3)
        for i in range(total_entities):
            w3_multicall.add(
                W3Multicall.Call(
                    self.addresses["op_registry"], "entity(uint256)(address)", i
                )
            )
        ops = w3_multicall.call()
        return [self.normalize_address(op) for op in ops]

    def get_op_nets(self, operator):
        operator = self.normalize_address(operator)
        nets = self.get_nets()
        w3_multicall = W3Multicall(self.w3)
        for net in nets:
            w3_multicall.add(
                W3Multicall.Call(
                    self.addresses["op_net_opt_in"],
                    "isOptedIn(address,address)(bool)",
                    [operator, net["net"]],
                )
            )
        optins = w3_multicall.call()
        return [net for net, opted_in in zip(nets, optins) if opted_in]

    def get_net_ops(self, net):
        net = self.normalize_address(net)
        ops = self.get_ops()
        w3_multicall = W3Multicall(self.w3)
        for op in ops:
            w3_multicall.add(
                W3Multicall.Call(
                    self.addresses["op_net_opt_in"],
                    "isOptedIn(address,address)(bool)",
                    [op, net],
                )
            )
        optins = w3_multicall.call()
        return [op for op, opted_in in zip(ops, optins) if opted_in]

    def get_vaults(self):
        total_entities = (
            self.contracts["vault_factory"].functions.totalEntities().call()
        )
        w3_multicall = W3Multicall(self.w3)
        for i in range(total_entities):
            w3_multicall.add(
                W3Multicall.Call(
                    self.addresses["vault_factory"], "entity(uint256)(address)", i
                )
            )
        vaults = w3_multicall.call()
        vaults = [self.normalize_address(vault) for vault in vaults]
        w3_multicall = W3Multicall(self.w3)
        for vault in vaults:
            w3_multicall.add(W3Multicall.Call(vault, "collateral()(address)"))
            w3_multicall.add(W3Multicall.Call(vault, "activeStake()(uint256)"))
            w3_multicall.add(W3Multicall.Call(vault, "delegator()(address)"))
            w3_multicall.add(W3Multicall.Call(vault, "slasher()(address)"))
        data = w3_multicall.call()
        results = []
        n = 4
        for i, vault in enumerate(vaults):
            results.append(
                {
                    "vault": vault,
                    "collateral": self.normalize_address(data[n * i]),
                    "tvl": data[n * i + 1],
                    "delegator": self.normalize_address(data[n * i + 2]),
                    "slasher": self.normalize_address(data[n * i + 3]),
                    "delegator_type": -1,
                    "slasher_type": -1,
                    "delegator_operator": -1,
                    "delegator_network": -1,
                }
            )

        w3_multicall = W3Multicall(self.w3)
        rev_result_idxs = []
        for idx, vault_info in enumerate(results):
            if vault_info["delegator"] != "0x0000000000000000000000000000000000000000":
                w3_multicall.add(
                    W3Multicall.Call(vault_info["delegator"], "TYPE()(uint64)")
                )
                rev_result_idxs.append((idx, "delegator_type"))
            if vault_info["slasher"] != "0x0000000000000000000000000000000000000000":
                w3_multicall.add(
                    W3Multicall.Call(vault_info["slasher"], "TYPE()(uint64)")
                )
                rev_result_idxs.append((idx, "slasher_type"))
        response = w3_multicall.call()
        for (idx, role), response_value in zip(rev_result_idxs, response):
            results[idx][role] = response_value

        if vault_info["delegator"] != "0x0000000000000000000000000000000000000000":
            w3_multicall = W3Multicall(self.w3)
            rev_result_idxs = []
            for idx, vault_info in enumerate(results):
                if vault_info["delegator_type"] in [2, 3]:
                    w3_multicall.add(
                        W3Multicall.Call(vault_info["delegator"], "operator()(address)")
                    )
                    rev_result_idxs.append((idx, "delegator_operator"))
                if vault_info["delegator_type"] in [3]:
                    w3_multicall.add(
                        W3Multicall.Call(vault_info["delegator"], "network()(address)")
                    )
                    rev_result_idxs.append((idx, "delegator_network"))
            response = w3_multicall.call()
            for (idx, role), response_value in zip(rev_result_idxs, response):
                results[idx][role] = response_value

        return results

    def get_net_vaults(self, net):
        """Fetch all vaults in a given network."""
        net = self.normalize_address(net)
        vaults = self.get_vaults()
        vaults = [
            vault
            for vault in vaults
            if vault["delegator"] != "0x0000000000000000000000000000000000000000"
            and (
                vault["delegator_type"] not in [3] or vault["delegator_network"] == net
            )
        ]
        w3_multicall = W3Multicall(self.w3)
        for vault in vaults:
            for subnet_id in self.SUBNETWORKS:
                if vault["delegator_type"] in [0, 1, 2]:
                    w3_multicall.add(
                        W3Multicall.Call(
                            vault["delegator"],
                            "networkLimit(bytes32)(uint256)",
                            bytes.fromhex(self.get_subnetwork(net, subnet_id)[2:]),
                        )
                    )
                elif vault["delegator_type"] in [3]:
                    w3_multicall.add(
                        W3Multicall.Call(
                            vault["delegator"],
                            "maxNetworkLimit(bytes32)(uint256)",
                            bytes.fromhex(self.get_subnetwork(net, subnet_id)[2:]),
                        )
                    )

        limits = w3_multicall.call()
        results = []
        i = 0
        for vault in vaults:
            vault_limit = {}
            for subnet_id in self.SUBNETWORKS:
                limit = limits[i]
                if limit and limit > 0:
                    vault_limit[subnet_id] = limit
                i += 1
            if len(vault_limit):
                results.append({"limit": vault_limit, **vault})

        return results

    def get_net_ops_vaults(self, net):
        """Fetch the stakes of all operators in a given network."""
        net = self.normalize_address(net)
        vaults = self.get_net_vaults(net)
        ops = self.get_net_ops(net)

        w3_multicall = W3Multicall(self.w3)
        for op in ops:
            for vault in vaults:
                for subnet_id in self.SUBNETWORKS:
                    w3_multicall.add(
                        W3Multicall.Call(
                            vault["delegator"],
                            "stake(bytes32,address)(uint256)",
                            [
                                bytes.fromhex(self.get_subnetwork(net, subnet_id)[2:]),
                                op,
                            ],
                        )
                    )

        stakes = w3_multicall.call()
        results = [{"op": op, "vaults": []} for op in ops]
        i = 0
        for op_idx in range(len(ops)):
            for vault in vaults:
                vault_stake = {}
                for subnet_id in self.SUBNETWORKS:
                    stake = stakes[i]
                    if stake and stake > 0:
                        vault_stake[subnet_id] = stake
                    i += 1
                if len(vault_stake):
                    results[op_idx]["vaults"].append({"stake": vault_stake, **vault})
        return results

    def get_vault_nets_ops_full(self, data):
        nets = self.get_vault_nets(data["vault"])
        ops = self.get_vault_ops(data["vault"])

        w3_multicall = W3Multicall(self.w3)
        for net in nets:
            for op in ops:
                for subnet_id in self.SUBNETWORKS:
                    w3_multicall.add(
                        W3Multicall.Call(
                            data["delegator"],
                            "stake(bytes32,address)(uint256)",
                            [
                                bytes.fromhex(
                                    self.get_subnetwork(net["net"], subnet_id)[2:]
                                ),
                                op,
                            ],
                        )
                    )

        stakes = w3_multicall.call()
        results = [{"net": net["net"], "ops": []} for net in nets]
        i = 0
        for net_idx in range(len(nets)):
            for op in ops:
                op_stakes = {}
                for subnet_id in self.SUBNETWORKS:
                    stake = stakes[i]
                    if stake and stake > 0:
                        op_stakes[subnet_id] = stake
                    i += 1
                if len(op_stakes):
                    results[net_idx]["ops"].append({"stake": op_stakes, "op": op})

        return results

    def get_op_nets_vaults(self, op):
        """Fetch stakes of an operator in all networks."""
        op = self.normalize_address(op)
        nets = self.get_op_nets(op)

        w3_multicall = W3Multicall(self.w3)
        net_vaults = {}
        for net in nets:
            net_vaults[net["net"]] = self.get_net_vaults(net["net"])
            for vault in net_vaults[net["net"]]:
                for subnet_id in self.SUBNETWORKS:
                    w3_multicall.add(
                        W3Multicall.Call(
                            vault["delegator"],
                            "stake(bytes32,address)(uint256)",
                            [
                                bytes.fromhex(
                                    self.get_subnetwork(net["net"], subnet_id)[2:]
                                ),
                                op,
                            ],
                        )
                    )

        stakes = w3_multicall.call()
        results = [{"net": net["net"], "vaults": []} for net in nets]
        i = 0
        for net_idx in range(len(nets)):
            for vault in net_vaults[nets[net_idx]["net"]]:
                vault_stake = {}
                for subnet_id in self.SUBNETWORKS:
                    stake = stakes[i]
                    if stake and stake > 0:
                        vault_stake[subnet_id] = stake
                    i += 1
                if len(vault_stake):
                    results[net_idx]["vaults"].append({"stake": vault_stake, **vault})

        return results

    def get_vault_ops(self, vault):
        """Get all operators that are opted into a given vault."""
        vault = self.normalize_address(vault)
        ops = self.get_ops()
        w3_multicall = W3Multicall(self.w3)

        for op in ops:
            w3_multicall.add(
                W3Multicall.Call(
                    self.addresses["op_vault_opt_in"],
                    "isOptedIn(address,address)(bool)",
                    [op, vault],
                )
            )

        optins = w3_multicall.call()
        return [op for op, opted_in in zip(ops, optins) if opted_in]

    def get_vault_nets(self, vault):
        """Get all networks associated with a given vault."""
        vault = self.normalize_address(vault)
        nets = self.get_nets()
        delegator = self.get_delegator(vault)

        w3_multicall = W3Multicall(self.w3)
        for net in nets:
            for subnet_id in self.SUBNETWORKS:
                w3_multicall.add(
                    W3Multicall.Call(
                        delegator,
                        "maxNetworkLimit(bytes32)(uint256)",
                        bytes.fromhex(self.get_subnetwork(net["net"], subnet_id)[2:]),
                    )
                )

        net_associations = w3_multicall.call()

        results = []
        i = 0
        for net in nets:
            network_limit = {}
            for subnet_id in self.SUBNETWORKS:
                associated = net_associations[i]
                if associated and associated > 0:
                    network_limit[subnet_id] = associated
                i += 1
            if len(network_limit):
                results.append({"net": net["net"], "limit": network_limit})

        return results

    def get_vault_nets_ops(self, vault):
        """Get all operators opted into the vault and their associated networks."""
        vault = self.normalize_address(vault)
        vault_ops = self.get_vault_ops(vault)
        vault_nets = self.get_vault_nets(vault)

        results = {}
        for net in vault_nets:
            w3_multicall = W3Multicall(self.w3)
            for op in vault_ops:
                w3_multicall.add(
                    W3Multicall.Call(
                        self.addresses["op_net_opt_in"],
                        "isOptedIn(address,address)(bool)",
                        [op, net["net"]],
                    )
                )
            results[net["net"]] = [
                op for op, opted_in in zip(vault_ops, w3_multicall.call()) if opted_in
            ]

        return results

    def get_op_opted_in_vault(self, operator, vault):
        """Check if an operator is opted into a vault."""
        operator = self.normalize_address(operator)
        vault = self.normalize_address(vault)
        return (
            self.contracts["op_vault_opt_in"]
            .functions.isOptedIn(operator, vault)
            .call()
        )

    def get_op_opted_in_net(self, operator, net):
        """Check if an operator is opted into a network."""
        operator = self.normalize_address(operator)
        net = self.normalize_address(net)
        return self.contracts["op_net_opt_in"].functions.isOptedIn(operator, net).call()

    def get_resolver_set_epoch_delay(self, slasher_address):
        slasher_address = self.normalize_address(slasher_address)
        return self.get_data("veto_slasher", slasher_address, "resolverSetEpochsDelay")

    def get_resolver(self, slasher_address, subnetwork):
        slasher_address = self.normalize_address(slasher_address)
        return self.normalize_address(
            self.get_data("veto_slasher", slasher_address, "resolver", subnetwork, "0x")
        )

    def get_pending_resolver(self, slasher_address, subnetwork):
        slasher_address = self.normalize_address(slasher_address)
        timestamp = 2**48 - 1
        return self.normalize_address(
            self.get_data(
                "veto_slasher",
                slasher_address,
                "resolverAt",
                subnetwork,
                timestamp,
                "0x",
            )
        )

    def get_entity_type(self, entity_address):
        entity_address = self.normalize_address(entity_address)
        return self.get_data("entity", entity_address, "TYPE")

    def get_vault_epoch_duration(self, vault_address):
        vault_address = self.normalize_address(vault_address)
        return self.get_data("vault", vault_address, "epochDuration")

    def get_vault_current_epoch(self, vault_address):
        vault_address = self.normalize_address(vault_address)
        return self.get_data("vault", vault_address, "currentEpoch")

    def get_vault_current_epoch_start(self, vault_address):
        vault_address = self.normalize_address(vault_address)
        return self.get_data("vault", vault_address, "currentEpochStart")

    def get_max_network_limit(self, delegator_address, subnetwork):
        delegator_address = self.normalize_address(delegator_address)
        return self.get_data(
            "full_restake_delegator", delegator_address, "maxNetworkLimit", subnetwork
        )

    def get_network_limit(self, delegator_address, subnetwork):
        delegator_address = self.normalize_address(delegator_address)
        return self.get_data(
            "full_restake_delegator", delegator_address, "networkLimit", subnetwork
        )

    def get_operator_network_limit(
        self, delegator_address, subnetwork, operator_address
    ):
        delegator_address = self.normalize_address(delegator_address)
        operator_address = self.normalize_address(operator_address)
        return self.get_data(
            "full_restake_delegator",
            delegator_address,
            "operatorNetworkLimit",
            subnetwork,
            operator_address,
        )

    def get_operator_network_shares(
        self, delegator_address, subnetwork, operator_address
    ):
        delegator_address = self.normalize_address(delegator_address)
        operator_address = self.normalize_address(operator_address)
        return self.get_data(
            "network_restake_delegator",
            delegator_address,
            "operatorNetworkShares",
            subnetwork,
            operator_address,
        )

    def get_total_operator_network_shares(self, delegator_address, subnetwork):
        delegator_address = self.normalize_address(delegator_address)
        return self.get_data(
            "network_restake_delegator",
            delegator_address,
            "totalOperatorNetworkShares",
            subnetwork,
        )

    def get_stake(self, vault_address, subnetwork, operator_address):
        vault_address = self.normalize_address(vault_address)
        operator_address = self.normalize_address(operator_address)

        delegator_address = self.get_delegator(vault_address)

        return self.get_data(
            "delegator", delegator_address, "stake", subnetwork, operator_address
        )

    def get_wei_amount(self, token, amount):
        token = self.normalize_address(token)
        meta = self.get_token_meta(token)
        wei_amount = int(amount * 10 ** meta["decimals"])
        if wei_amount >= 2**256:
            raise ValueError("Amount is too large")
        return wei_amount

    def get_token_amount(self, token, wei_amount):
        token = self.normalize_address(token)
        meta = self.get_token_meta(token)
        return wei_amount / 10 ** meta["decimals"]

    def get_allowance(self, token, owner, spender):
        token = self.normalize_address(token)
        owner = self.normalize_address(owner)
        spender = self.normalize_address(spender)

        return self.get_data("erc20", token, "allowance", owner, spender)

    def get_active_balance(self, vault_address, account):
        vault_address = self.normalize_address(vault_address)
        account = self.normalize_address(account)

        return self.get_data("vault", vault_address, "activeBalanceOf", account)

    def get_withdrawals(self, vault_address, epoch, account):
        vault_address = self.normalize_address(vault_address)
        account = self.normalize_address(account)

        return self.get_data("vault", vault_address, "withdrawalsOf", epoch, account)

    def get_withdrawals_claimed(self, vault_address, epoch, account):
        vault_address = self.normalize_address(vault_address)
        account = self.normalize_address(account)

        return self.get_data(
            "vault", vault_address, "isWithdrawalsClaimed", epoch, account
        )

    def timestamp_to_datetime(self, timestamp):
        return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")

    def get_operator_network_opt_in_signature(
        self, private_key, ledger, ledger_address, where, duration
    ):
        where = self.normalize_address(where)
        who = self.get_address(private_key, ledger, ledger_address)
        entity = "op_net_opt_in"
        nonce = self.get_data(entity, self.addresses[entity], "nonces", who, where)
        deadline = int(time()) + duration
        return self.process_type_data_sign(
            private_key,
            ledger,
            ledger_address,
            "OperatorNetworkOptInService",
            "1",
            self.addresses[entity],
            {
                "OptIn": [
                    {"name": "who", "type": "address"},
                    {"name": "where", "type": "address"},
                    {"name": "nonce", "type": "uint256"},
                    {"name": "deadline", "type": "uint48"},
                ],
            },
            {
                "who": who,
                "where": where,
                "nonce": nonce,
                "deadline": deadline,
            },
            success_message=f"""
Operator: {who}
Network: {where}
Nonce: {nonce}
Deadline: {deadline} ({self.timestamp_to_datetime(deadline)})
"""
            + "Success! Your signature is: {}",
        )

    def get_operator_network_opt_out_signature(
        self, private_key, ledger, ledger_address, where, duration
    ):
        where = self.normalize_address(where)
        who = self.get_address(private_key, ledger, ledger_address)
        entity = "op_net_opt_in"
        nonce = self.get_data(entity, self.addresses[entity], "nonces", who, where)
        deadline = int(time()) + duration
        return self.process_type_data_sign(
            private_key,
            ledger,
            ledger_address,
            "OperatorNetworkOptInService",
            "1",
            self.addresses[entity],
            {
                "OptOut": [
                    {"name": "who", "type": "address"},
                    {"name": "where", "type": "address"},
                    {"name": "nonce", "type": "uint256"},
                    {"name": "deadline", "type": "uint48"},
                ],
            },
            {
                "who": who,
                "where": where,
                "nonce": nonce,
                "deadline": deadline,
            },
            success_message=f"""
Operator: {who}
Network: {where}
Nonce: {nonce}
Deadline: {deadline} ({self.timestamp_to_datetime(deadline)})
"""
            + "Success! Your signature is: {}",
        )

    def get_operator_vault_opt_in_signature(
        self, private_key, ledger, ledger_address, where, duration
    ):
        where = self.normalize_address(where)
        who = self.get_address(private_key, ledger, ledger_address)
        entity = "op_vault_opt_in"
        nonce = self.get_data(entity, self.addresses[entity], "nonces", who, where)
        deadline = int(time()) + duration
        return self.process_type_data_sign(
            private_key,
            ledger,
            ledger_address,
            "OperatorVaultOptInService",
            "1",
            self.addresses[entity],
            {
                "OptIn": [
                    {"name": "who", "type": "address"},
                    {"name": "where", "type": "address"},
                    {"name": "nonce", "type": "uint256"},
                    {"name": "deadline", "type": "uint48"},
                ],
            },
            {
                "who": who,
                "where": where,
                "nonce": nonce,
                "deadline": deadline,
            },
            success_message=f"""
Operator: {who}
Vault: {where}
Nonce: {nonce}
Deadline: {deadline} ({self.timestamp_to_datetime(deadline)})
"""
            + "Success! Your signature is: {}",
        )

    def get_operator_vault_opt_out_signature(
        self, private_key, ledger, ledger_address, where, duration
    ):
        where = self.normalize_address(where)
        who = self.get_address(private_key, ledger, ledger_address)
        entity = "op_vault_opt_in"
        nonce = self.get_data(entity, self.addresses[entity], "nonces", who, where)
        deadline = int(time()) + duration
        return self.process_type_data_sign(
            private_key,
            ledger,
            ledger_address,
            "OperatorVaultOptInService",
            "1",
            self.addresses[entity],
            {
                "OptOut": [
                    {"name": "who", "type": "address"},
                    {"name": "where", "type": "address"},
                    {"name": "nonce", "type": "uint256"},
                    {"name": "deadline", "type": "uint48"},
                ],
            },
            {
                "who": who,
                "where": where,
                "nonce": nonce,
                "deadline": deadline,
            },
            success_message=f"""
Operator: {who}
Vault: {where}
Nonce: {nonce}
Deadline: {deadline} ({self.timestamp_to_datetime(deadline)})
"""
            + "Success! Your signature is: {}",
        )

    def decode_error_data(self, error_data: str):
        if not error_data.startswith("0x"):
            error_data = "0x" + error_data
        if len(error_data) < 10:
            return None

        selector = error_data[:10]
        encoded_args = error_data[10:]

        if selector in self._error_selectors:
            error_name, input_types = self._error_selectors[selector]
            if not input_types:
                return (error_name, [])
            encoded_bytes = bytes.fromhex(encoded_args)
            decoded = abi.decode(input_types, encoded_bytes)

            return (error_name, decoded)
        elif selector == "0x08c379a0":
            # "Error(string)"
            encoded_bytes = bytes.fromhex(encoded_args)
            reason_str = abi.decode(["string"], encoded_bytes)[0]
            return ("Error(string)", [reason_str])
        elif selector == "0x4e487b71":
            # "Panic(uint256)"
            encoded_bytes = bytes.fromhex(encoded_args)
            panic_code = abi.decode(["uint256"], encoded_bytes)[0]
            return ("Panic(uint256)", [panic_code])

        return None

    def process_error(self, e):
        raw_msg = str(e.args[0])
        m = re.search(r"(0x[0-9a-fA-F]+)", raw_msg)
        if m:
            revert_hex = m.group(1)
            decoded = self.decode_error_data(revert_hex)
            if decoded:
                error_name, params = decoded
                print(f"Reverted with {error_name}({params if params else ''})")
            else:
                print(f"Reverted with unknown error data: {revert_hex}")
        else:
            print(f"Reverted, no error data found: {raw_msg}")

    def print_indented(self, *args, indent=2):
        print(" " * indent + " ".join(map(str, args)))

    def get_data(self, entity, address, function_name, *args, **kwargs):
        address = self.normalize_address(address)
        contract = self.w3.eth.contract(address=address, abi=self.ABIS[entity])

        return contract.functions[function_name](*args).call(kwargs)

    def get_address(self, private_key, ledger, ledger_address):
        if ledger_address:
            ledger_address = self.normalize_address(ledger_address)

        if ledger:
            if ledger_address:
                address = ledger_address
            else:
                address = ledgereth.accounts.get_accounts()[0].address

        else:
            address = Account.from_key(private_key).address

        return self.normalize_address(address)

    def get_transaction(self, who, entity, address, function_name, *args, **kwargs):
        who = self.normalize_address(who)
        address = self.normalize_address(address)
        contract = self.w3.eth.contract(address=address, abi=self.ABIS[entity])

        return contract.functions[function_name](*args).build_transaction(
            {
                "chainId": self.CHAIN_IDS[self.chain],
                "from": who,
                "nonce": self.w3.eth.get_transaction_count(who),
                **kwargs,
            }
        )

    def get_transaction_ledger(
        self, ledger_account, entity, address, function_name, *args, **kwargs
    ):
        address = self.normalize_address(address)
        tx = self.get_transaction(
            ledger_account.address, entity, address, function_name, *args, **kwargs
        )

        print("Sign transaction on Ledger device")
        return ledgereth.transactions.create_transaction(
            destination=tx["to"],
            amount=tx["value"],
            gas=tx["gas"],
            max_fee_per_gas=tx["maxFeePerGas"],
            max_priority_fee_per_gas=tx["maxPriorityFeePerGas"],
            data=tx["data"],
            nonce=tx["nonce"],
            chain_id=tx["chainId"],
            sender_path=ledger_account.path,
        )

    def send_raw_transaction_and_wait(self, rawTransaction):
        tx_hash = self.w3.eth.send_raw_transaction(rawTransaction)
        print(f"Transaction sent: {tx_hash.hex()}, waiting...")
        return self.w3.eth.wait_for_transaction_receipt(tx_hash)

    def send_transaction(self, tx, private_key):
        signed_tx = self.w3.eth.account.sign_transaction(tx, private_key)
        return self.send_raw_transaction_and_wait(signed_tx.rawTransaction)

    def send_transaction_ledger(self, tx):
        return self.send_raw_transaction_and_wait(tx.rawTransaction)

    def process_write_transaction(
        self,
        private_key,
        ledger,
        ledger_address,
        entity,
        to,
        function_name,
        *args,
        success_message="Success!",
    ):
        to = self.normalize_address(to)
        try:
            if ledger_address:
                ledger_address = self.normalize_address(ledger_address)

            if ledger:
                if ledger_address:
                    account = ledgereth.accounts.find_account(ledger_address)
                else:
                    account = ledgereth.accounts.get_accounts()[0]

                tx = self.get_transaction_ledger(
                    account, entity, to, function_name, *args
                )

                tx_receipt = self.send_transaction_ledger(tx)

                ledgereth.comms.DONGLE_CACHE = None

            else:
                who = Account.from_key(private_key).address

                tx = self.get_transaction(who, entity, to, function_name, *args)

                tx_receipt = self.send_transaction(tx, private_key)

            print(success_message)

            return tx_receipt
        except Exception as e:
            self.process_error(e)

    def get_domain_data(self, name, version, verifyingContract):
        verifyingContract = self.normalize_address(verifyingContract)
        return {
            "name": name,
            "version": version,
            "chainId": self.CHAIN_IDS[self.chain],
            "verifyingContract": str(verifyingContract),
        }

    def get_signable_message_from_typed_data(
        self, name, version, verifyingContract, message_types, message_data
    ):
        verifyingContract = self.normalize_address(verifyingContract)
        return encode_typed_data(
            self.get_domain_data(name, version, verifyingContract),
            message_types,
            message_data,
        )

    def sign_typed_data_ledger(self, account, signable_message):
        domain_hash = signable_message.header
        message_hash = signable_message.body

        print("Sign data on Ledger device")

        return sign_typed_data_draft(
            domain_hash, message_hash, sender_path=account.path
        )

    def sign_typed_data(
        self, private_key, name, version, verifyingContract, message_types, message_data
    ):
        verifyingContract = self.normalize_address(verifyingContract)
        return Account.sign_typed_data(
            private_key,
            self.get_domain_data(name, version, verifyingContract),
            message_types,
            message_data,
        )

    def process_type_data_sign(
        self,
        private_key,
        ledger,
        ledger_address,
        name,
        version,
        verifyingContract,
        message_types,
        message_data,
        success_message="Success! Your signature is: {}",
    ):
        verifyingContract = self.normalize_address(verifyingContract)
        try:
            if ledger_address:
                ledger_address = self.normalize_address(ledger_address)

            if ledger:
                if ledger_address:
                    account = ledgereth.accounts.find_account(ledger_address)
                else:
                    account = ledgereth.accounts.get_accounts()[0]

                signable_message = self.get_signable_message_from_typed_data(
                    name,
                    version,
                    verifyingContract,
                    message_types,
                    message_data,
                )

                signed_message = self.sign_typed_data_ledger(account, signable_message)
                signature = signed_message.signature

            else:
                signed_message = self.sign_typed_data(
                    private_key,
                    name,
                    version,
                    verifyingContract,
                    message_types,
                    message_data,
                )
                signature = signed_message.signature.hex()

            print(success_message.format(signature))

            return signature

        except Exception as e:
            self.process_error(e)

    def process_request(self, request_text):
        response = input(f"{request_text}")

        if response != "y":
            print("Cancel")
            return False
        else:
            return True


### GENERAL CLI COMMANDS ###


@click.group()
@click.option(
    "--chain",
    default="mainnet",
    type=chain_type,
    show_default=True,
    help="Chain ID to use.",
)
@click.option(
    "--provider",
    help="Ethereum provider URL [http(s)].",
)
@click.pass_context
def cli(ctx, chain, provider):
    ctx.obj = SymbioticCLI(chain, provider)


## GENERAL NETWORK RELATED CLI COMMANDS ##


@cli.command()
@click.argument("address", type=address_type)
@click.pass_context
def isnet(ctx, address):
    """Check if address is network.

    \b
    ADDRESS - an address to check
    """
    address = ctx.obj.normalize_address(address)
    is_net = ctx.obj.contracts["net_registry"].functions.isEntity(address).call()
    print(is_net)


@cli.command()
@click.argument("network_address", type=address_type)
@click.pass_context
def middleware(ctx, network_address):
    """Get network middleware address.

    \b
    NETWORK_ADDRESS - an address of the network to get a middleware for
    """
    network_address = ctx.obj.normalize_address(network_address)
    middleware_address = ctx.obj.get_middleware(network_address)
    print(middleware_address)


@cli.command()
@click.option(
    "--full",
    is_flag=True,
    help="Show full data",
)
@click.pass_context
def nets(ctx, full):
    """List all networks."""
    nets = ctx.obj.get_nets()
    print(f"All networks [{len(nets)} total]:")

    if full:
        for i, net in enumerate(nets):
            op_vaults = ctx.obj.get_net_ops_vaults(net["net"])
            nets[i]["ops"] = len(op_vaults)
            vaults = {vault["vault"] for op in op_vaults for vault in op["vaults"]}
            nets[i]["vaults"] = len(vaults)

    for net in nets:
        ctx.obj.print_indented(f'Network: {net["net"]}', indent=2)
        ctx.obj.print_indented(f'Middleware: {net["middleware"]}', indent=4)

        if full:
            ctx.obj.print_indented(f'Operators: {net["ops"]} total', indent=4)
            ctx.obj.print_indented(f'Vaults: {net["vaults"]} total', indent=4)
        ctx.obj.print_indented("", indent=0)


@cli.command()
@click.argument("network_address", type=address_type)
@click.pass_context
def netops(ctx, network_address):
    """List all operators opted in network.

    \b
    NETWORK_ADDRESS - an address of the network to get operators for
    """
    network_address = ctx.obj.normalize_address(network_address)
    print(f"Network: {network_address}")
    ops = ctx.obj.get_net_ops(network_address)
    print(f"Operators [{len(ops)} total]:")
    for op in ops:
        ctx.obj.print_indented(f"Operator: {op}")


@cli.command()
@click.argument("network_address", type=address_type)
@click.pass_context
def netstakes(ctx, network_address):
    """Show stakes of all operators in network.

    \b
    NETWORK_ADDRESS - an address of the network to get a whole stake data for
    """
    network_address = ctx.obj.normalize_address(network_address)
    print(f"Network: {network_address}")
    print(f"Middleware: {ctx.obj.get_middleware(network_address)}")

    opsvaults = ctx.obj.get_net_ops_vaults(network_address)
    print(f"Operators [{len(opsvaults)} total]:")
    total_stakes = {}
    for op in opsvaults:
        ctx.obj.print_indented(f'Operator: {op["op"]}', indent=2)
        collaterals = {}
        for vault in op["vaults"]:
            vault["token_meta"] = ctx.obj.get_token_meta(vault["collateral"])
            if vault["collateral"] not in collaterals:
                collaterals[vault["collateral"]] = []
            collaterals[vault["collateral"]].append(vault)

        total_op_stake = ""
        for collateral, vaults in collaterals.items():
            stakes_sum = 0
            token_meta = ctx.obj.get_token_meta(collateral)
            ctx.obj.print_indented(
                f'Collateral: {collateral} ({token_meta["symbol"]})', indent=4
            )
            for vault in vaults:
                ctx.obj.print_indented(f'Vault: {vault["vault"]}', indent=6)
                ctx.obj.print_indented(
                    f'Type: {ctx.obj.DELEGATOR_TYPES_NAMES[vault["delegator_type"]]} / {ctx.obj.SLASHER_TYPES_NAMES[vault["slasher_type"]]}',
                    indent=8,
                )
                stake = sum(vault["stake"].values())
                ctx.obj.print_indented(
                    f'Stake: {stake / 10 ** token_meta["decimals"]}', indent=8
                )
                stakes_sum += stake
            total_op_stake += (
                f'{stakes_sum / 10 ** token_meta["decimals"]} {token_meta["symbol"]} + '
            )
            if collateral not in total_stakes:
                total_stakes[collateral] = 0
            total_stakes[collateral] += stakes_sum

        if total_op_stake:
            ctx.obj.print_indented("Total stake:", total_op_stake[:-3], indent=4)
        else:
            ctx.obj.print_indented("Total stake: 0", indent=4)
        print("")

    print("Total stakes:")
    for collateral, stakes in total_stakes.items():
        token_meta = ctx.obj.get_token_meta(collateral)
        ctx.obj.print_indented(
            f'Collateral {collateral} ({token_meta["symbol"]}): {stakes / 10 ** token_meta["decimals"]}',
            indent=2,
        )


## GENERAL OPERATOR RELATED CLI COMMANDS ##


@cli.command()
@click.argument("address", type=address_type)
@click.pass_context
def isop(ctx, address):
    """Check if address is operator.

    \b
    ADDRESS - an address to check
    """
    address = ctx.obj.normalize_address(address)
    is_op = ctx.obj.contracts["op_registry"].functions.isEntity(address).call()
    print(is_op)


@cli.command()
@click.pass_context
def ops(ctx):
    """List all operators."""
    ops = ctx.obj.get_ops()
    print(f"All operators [{len(ops)} total]:")
    for op in ops:
        ctx.obj.print_indented(f"Operator: {op}", indent=2)


@cli.command()
@click.argument("operator_address", type=address_type)
@click.argument("vault_address", type=address_type)
@click.argument("network_address", type=address_type)
@click.pass_context
def op_vault_net_stake(ctx, operator_address, vault_address, network_address):
    """Get operator stake in vault for network.

    \b
    OPERATOR_ADDRESS - an address of the operator to get a stake of
    VAULT_ADDRESS - an address of the vault to get a stake at
    NETWORK_ADDRESS - an address of the network to get a stake for
    """
    operator_address = ctx.obj.normalize_address(operator_address)
    vault_address = ctx.obj.normalize_address(vault_address)
    network_address = ctx.obj.normalize_address(network_address)

    delegator = ctx.obj.get_delegator(vault_address)
    delegator_type = ctx.obj.get_entity_type(delegator)

    print(f"Operator stake in vault = {vault_address}")
    print()
    for subnetwork_id in ctx.obj.SUBNETWORKS:
        subnetwork = ctx.obj.get_subnetwork(network_address, subnetwork_id)

        stake = ctx.obj.get_stake(vault_address, subnetwork, operator_address)
        collateral = ctx.obj.get_collateral(vault_address)
        token_meta = ctx.obj.get_token_meta(collateral)
        stake_normalized = stake / 10 ** token_meta["decimals"]
        collateral_symbol = token_meta["symbol"]

        if delegator_type == 0:
            operator_network_shares = ctx.obj.get_operator_network_shares(
                delegator, subnetwork, operator_address
            )
            total_operator_network_shares = ctx.obj.get_total_operator_network_shares(
                delegator, subnetwork
            )

            percent = (
                0
                if total_operator_network_shares == 0
                else operator_network_shares / total_operator_network_shares * 100
            )

            print(
                f"for subnetwork = {subnetwork} is {stake_normalized} {collateral_symbol}\nwhich is {percent}% ({operator_network_shares} / {total_operator_network_shares} in shares) of network stake"
            )
        else:
            print(
                f"for subnetwork = {subnetwork} is {stake_normalized} {collateral_symbol}"
            )
        print()


@cli.command()
@click.argument("operator_address", type=address_type)
@click.pass_context
def opnets(ctx, operator_address):
    """List all networks where operator is opted in.

    \b
    OPERATOR_ADDRESS - an address of the operator to get networks for
    """
    operator_address = ctx.obj.normalize_address(operator_address)
    print(f"Operator: {operator_address}")
    nets = ctx.obj.get_op_nets(operator_address)
    print(f"Networks [{len(nets)} total]:")
    for net in nets:
        print(f'  Network: {net["net"]}')


@cli.command()
@click.argument("operator_address", type=address_type)
@click.pass_context
def opstakes(ctx, operator_address):
    """Show operator stakes in all networks.

    \b
    OPERATOR_ADDRESS - an address of the operator to get a whole stake data for
    """
    operator_address = ctx.obj.normalize_address(operator_address)
    print(f"Operator: {operator_address}")

    netsvaults = ctx.obj.get_op_nets_vaults(operator_address)
    print(f"Networks [{len(netsvaults)} total]:")
    total_stakes = {}
    for net in netsvaults:
        ctx.obj.print_indented(f'Network: {net["net"]}', indent=2)
        collaterals = {}
        for vault in net["vaults"]:
            vault["token_meta"] = ctx.obj.get_token_meta(vault["collateral"])
            if vault["collateral"] not in collaterals:
                collaterals[vault["collateral"]] = []
            collaterals[vault["collateral"]].append(vault)

        total_net_stake = ""
        for collateral, vaults in collaterals.items():
            stakes_sum = 0
            token_meta = ctx.obj.get_token_meta(collateral)
            ctx.obj.print_indented(
                f'Collateral: {collateral} ({token_meta["symbol"]})', indent=4
            )
            for vault in vaults:
                ctx.obj.print_indented(f'Vault: {vault["vault"]}', indent=6)
                ctx.obj.print_indented(
                    f'Type: {ctx.obj.DELEGATOR_TYPES_NAMES[vault["delegator_type"]]} / {ctx.obj.SLASHER_TYPES_NAMES[vault["slasher_type"]]}',
                    indent=8,
                )
                stake = sum(vault["stake"].values())
                ctx.obj.print_indented(
                    f'Stake: {stake / 10 ** token_meta["decimals"]}', indent=8
                )
                stakes_sum += stake
            total_net_stake += (
                f'{stakes_sum / 10 ** token_meta["decimals"]} {token_meta["symbol"]} + '
            )
            if collateral not in total_stakes:
                total_stakes[collateral] = 0
            total_stakes[collateral] += stakes_sum

        if total_net_stake:
            ctx.obj.print_indented("Total stake:", total_net_stake[:-3], indent=4)
        else:
            ctx.obj.print_indented("Total stake: 0", indent=4)
        print("")

    print("Total stakes:")
    for collateral, stakes in total_stakes.items():
        token_meta = ctx.obj.get_token_meta(collateral)
        ctx.obj.print_indented(
            f'Collateral {collateral} ({token_meta["symbol"]}): {stakes / 10 ** token_meta["decimals"]}',
            indent=2,
        )


@cli.command()
@click.argument("operator_address", type=address_type)
@click.argument("vault_address", type=address_type)
@click.pass_context
def check_opt_in_vault(ctx, operator_address, vault_address):
    """Check if operator is opted in to a vault.

    \b
    OPERATOR_ADDRESS - an address of the operator to check an opt-in status of
    VAULT_ADDRESS - an address of the vault to check an opt-in status for
    """
    print(
        f"Operator = {operator_address} IS opted in to vault = {vault_address}"
        if ctx.obj.get_op_opted_in_vault(operator_address, vault_address)
        else f"Operator = {operator_address} IS NOT opted in to vault = {vault_address}"
    )


@cli.command()
@click.argument("operator_address", type=address_type)
@click.argument("network_address", type=address_type)
@click.pass_context
def check_opt_in_network(ctx, operator_address, network_address):
    """Check if operator is opted in to a network.

    \b
    OPERATOR_ADDRESS - an address of the operator to check an opt-in status of
    NETWORK_ADDRESS - an address of the network to check an opt-in status for
    """
    print(
        f"Operator = {operator_address} IS opted in to network = {network_address}"
        if ctx.obj.get_op_opted_in_net(operator_address, network_address)
        else f"Operator = {operator_address} IS NOT opted in to network = {network_address}"
    )


## GENERAL VAULT RELATED CLI COMMANDS ##


@cli.command()
@click.argument("address", type=address_type)
@click.pass_context
def isvault(ctx, address):
    """Check if address is vault.

    \b
    ADDRESS - an address to check
    """
    address = ctx.obj.normalize_address(address)
    is_vault = ctx.obj.contracts["vault_factory"].functions.isEntity(address).call()
    print(is_vault)


@cli.command()
@click.option(
    "--full",
    is_flag=True,
    help="Show full data",
)
@click.pass_context
def vaults(ctx, full):
    """List all vaults."""
    vaults = ctx.obj.get_vaults()
    print(f"All vaults [{len(vaults)} total]:")

    for vault in vaults:
        ctx.obj.print_indented(f'Vault: {vault["vault"]}')
        collateral_meta = ctx.obj.get_token_meta(vault["collateral"])
        ctx.obj.print_indented(
            f'Collateral: {vault["collateral"]} ({collateral_meta["symbol"]})', indent=4
        )
        ctx.obj.print_indented(
            f'Delegator: {vault["delegator"]} ({ctx.obj.DELEGATOR_TYPES_NAMES.get(vault["delegator_type"], "Unknown")})',
            indent=4,
        )
        slasher_type = ctx.obj.SLASHER_TYPES_NAMES.get(vault["slasher_type"], "Unknown")
        ctx.obj.print_indented(
            f'Slasher: {vault["slasher"]} ({slasher_type})', indent=4
        )
        ctx.obj.print_indented(
            f'TVL: {vault["tvl"] / 10 ** collateral_meta["decimals"]} {collateral_meta["symbol"]}\n',
            indent=4,
        )

        if full:
            vault_data = ctx.obj.get_vault_nets_ops_full(vault)
            ctx.obj.print_indented(f"Networks [{len(vault_data)} total]:", indent=4)
            ctx.obj.print_indented(
                f"Total delegated: {sum([sum(op['stake'].values()) for net_data in vault_data for op in net_data['ops']]) / 10 ** collateral_meta['decimals']} {collateral_meta['symbol']}",
                indent=4,
            )
            for net_data in vault_data:
                ctx.obj.print_indented(f"Network: {net_data['net']}", indent=6)
                ctx.obj.print_indented(
                    f"Operators [{len(net_data['ops'])} total]", indent=6
                )
                ctx.obj.print_indented(
                    f"Delegated to network: {sum([sum(op['stake'].values()) for op in net_data['ops']]) / 10 ** collateral_meta['decimals']} {collateral_meta['symbol']}",
                    indent=6,
                )
                print()
            print()


@cli.command()
@click.argument("vault_address", type=address_type)
@click.pass_context
def vaultops(ctx, vault_address):
    """List all operators opted into the given vault.

    \b
    VAULT_ADDRESS - an address of the vault to get all operators for
    """
    vault_address = ctx.obj.normalize_address(vault_address)
    ops = ctx.obj.get_vault_ops(vault_address)
    print(f"Vault: {vault_address}")
    print(f"Operators [{len(ops)} total]:")
    for op in ops:
        ctx.obj.print_indented(
            f"Operator: {op}",
            indent=2,
        )


@cli.command()
@click.argument("vault_address", type=address_type)
@click.pass_context
def vaultnets(ctx, vault_address):
    """List all networks associated with the given vault.

    \b
    VAULT_ADDRESS - an address of the vault to get all networks for
    """
    vault_address = ctx.obj.normalize_address(vault_address)
    nets = ctx.obj.get_vault_nets(vault_address)
    print(f"Vault: {vault_address}")
    print(f"Networks [{len(nets)} total]:")
    for net in nets:
        ctx.obj.print_indented(
            f"Network: {net['net']}",
            indent=2,
        )


@cli.command()
@click.argument("vault_address", type=address_type)
@click.pass_context
def vaultnetsops(ctx, vault_address):
    """List all operators and their associated networks for the given vault.

    \b
    VAULT_ADDRESS - an address of the vault to adjust the delegations for
    """
    vault_address = ctx.obj.normalize_address(vault_address)
    nets_ops = ctx.obj.get_vault_nets_ops(vault_address)
    print(f"Vault: {vault_address}")
    print(f"Networks [{len(nets_ops)} total]:")
    print("")

    for net in nets_ops:
        ctx.obj.print_indented(
            f"Network: {net}",
            indent=2,
        )
        ctx.obj.print_indented(
            f"Operators [{len(nets_ops[net])} total]:",
            indent=2,
        )
        for op in nets_ops[net]:
            ctx.obj.print_indented(
                f"Operator: {op}",
                indent=4,
            )
        print("")


## GENERAL STAKER RELATED CLI COMMANDS ##


@cli.command()
@click.argument("vault_address", type=address_type)
@click.argument("address", type=address_type)
@click.pass_context
def active_balance_of(ctx, vault_address, address):
    """Get an active balance of a given account at a particular vault.

    \b
    VAULT_ADDRESS - an address of the vault
    ADDRESS - an address to get an active balance for
    """
    vault_address = ctx.obj.normalize_address(vault_address)
    address = ctx.obj.normalize_address(address)

    token_address = ctx.obj.get_collateral(vault_address)
    symbol = ctx.obj.get_token_meta(token_address)["symbol"]
    active_balance_wei = ctx.obj.get_active_balance(vault_address, address)
    active_balance = ctx.obj.get_token_amount(token_address, active_balance_wei)
    print(f"{active_balance_wei} ({active_balance} {symbol})")


@cli.command()
@click.argument("vault_address", type=address_type)
@click.argument("epoch", type=uint256_type)
@click.argument("address", type=address_type)
@click.pass_context
def withdrawals_of(ctx, vault_address, epoch, address):
    """Get some epoch's withdrawals of a given account at a particular vault.

    \b
    VAULT_ADDRESS - an address of the vault
    EPOCH - an epoch to get withdrawals for
    ADDRESS - an address to get withdrawals for
    """
    vault_address = ctx.obj.normalize_address(vault_address)
    address = ctx.obj.normalize_address(address)

    token_address = ctx.obj.get_collateral(vault_address)
    symbol = ctx.obj.get_token_meta(token_address)["symbol"]
    withdrawals_wei = ctx.obj.get_withdrawals(vault_address, epoch, address)
    withdrawals = ctx.obj.get_token_amount(token_address, withdrawals_wei)
    print(f"{withdrawals_wei} ({withdrawals} {symbol})")


@cli.command()
@click.argument("vault_address", type=address_type)
@click.argument("epoch", type=uint256_type)
@click.argument("address", type=address_type)
@click.pass_context
def withdrawals_claimed(ctx, vault_address, epoch, address):
    """Check if some epoch's withdrawals of a given account at a particular vault are claimed.

    \b
    VAULT_ADDRESS - an address of the vault
    EPOCH - an epoch to check for
    ADDRESS - an address to get if the withdrawals are claimed for
    """
    vault_address = ctx.obj.normalize_address(vault_address)
    address = ctx.obj.normalize_address(address)

    withdrawals_claimed = ctx.obj.get_withdrawals_claimed(vault_address, epoch, address)
    print(withdrawals_claimed)


### NETWORK CLI COMMANDS ###


@cli.command()
@click.option(
    "--private-key", type=bytes32_type, help="Your private key for signing transactions"
)
@click.option(
    "--ledger",
    is_flag=True,
    help="Use a Ledger device for signing transactions instead of a private key",
)
@click.option(
    "--ledger-address",
    type=address_type,
    help="The Ledger account address to use for signing (defaults to the first account if not provided)",
)
@click.pass_context
def register_network(ctx, private_key, ledger, ledger_address):
    """Register the signer as a network."""

    if not private_key and not ledger:
        print("Private key or ledger is required")
        return

    ctx.obj.process_write_transaction(
        private_key,
        ledger,
        ledger_address,
        "net_registry",
        ctx.obj.addresses["net_registry"],
        "registerNetwork",
        success_message=f"Successfully registered as a network",
    )


@cli.command()
@click.argument("vault_address", type=address_type)
@click.argument("max_limit", type=uint256_type)
@click.argument("subnetwork_id", default=0, type=uint96_type)
@click.option(
    "--private-key", type=bytes32_type, help="Your private key for signing transactions"
)
@click.option(
    "--ledger",
    is_flag=True,
    help="Use a Ledger device for signing transactions instead of a private key",
)
@click.option(
    "--ledger-address",
    type=address_type,
    help="The Ledger account address to use for signing (defaults to the first account if not provided)",
)
@click.pass_context
def set_max_network_limit(
    ctx, vault_address, max_limit, subnetwork_id, private_key, ledger, ledger_address
):
    """Set a maximum network limit at the vault's delegator.

    \b
    VAULT_ADDRESS - an address of the vault to set a maximum limit for
    MAX_LIMIT - a maximum amount of stake a network is ready to get from the vault (in wei)
    SUBNETWORK_ID - an identifier of the subnetwork to set a maximum limit for (default is 0)
    """
    vault_address = ctx.obj.normalize_address(vault_address)

    delegator = ctx.obj.get_delegator(vault_address)

    ctx.obj.process_write_transaction(
        private_key,
        ledger,
        ledger_address,
        "delegator",
        delegator,
        "setMaxNetworkLimit",
        subnetwork_id,
        max_limit,
        success_message=f"Successfully set max limit = {max_limit} in vault = {vault_address}",
    )


@cli.command()
@click.argument("vault_address", type=address_type)
@click.argument("network_address", type=address_type)
@click.pass_context
def max_network_limit(ctx, vault_address, network_address):
    """Get a current maximum network limit for a subnetwork in a vault.

    \b
    VAULT_ADDRESS - an address of the vault to get a maximum network limit for
    NETWORK_ADDRESS - an address of the network to get a maximum network limit for
    """
    vault_address = ctx.obj.normalize_address(vault_address)
    network_address = ctx.obj.normalize_address(network_address)

    delegator = ctx.obj.get_delegator(vault_address)

    print()
    for subnetwork_id in ctx.obj.SUBNETWORKS:
        subnetwork = ctx.obj.get_subnetwork(network_address, subnetwork_id)

        max_network_limit = ctx.obj.get_max_network_limit(delegator, subnetwork)
        print(
            f"Maximum network limit for subnetwork = {subnetwork} at vault {vault_address} is {max_network_limit}"
        )
        print()


@cli.command()
@click.argument("vault_address", type=address_type)
@click.argument("network_address", type=address_type)
@click.pass_context
def resolver(ctx, vault_address, network_address):
    """Get a current resolver for a subnetwork in a vault.

    \b
    VAULT_ADDRESS - an address of the vault to get a resolver for
    NETWORK_ADDRESS - an address of the network to get a resolver for
    """
    vault_address = ctx.obj.normalize_address(vault_address)
    network_address = ctx.obj.normalize_address(network_address)

    slasher = ctx.obj.get_slasher(vault_address)
    slasher_type = ctx.obj.get_entity_type(slasher)

    if slasher_type != 1:
        print("It is not a VetoSlasher.")
        return

    print()
    for subnetwork_id in ctx.obj.SUBNETWORKS:
        subnetwork = ctx.obj.get_subnetwork(network_address, subnetwork_id)

        resolver = ctx.obj.get_resolver(slasher, subnetwork)
        print(
            f"Resolver for subnetwork = {subnetwork} at vault {vault_address} is {resolver}"
        )
        print()


@cli.command()
@click.argument("vault_address", type=address_type)
@click.argument("network_address", type=address_type)
@click.pass_context
def pending_resolver(ctx, vault_address, network_address):
    """Get a pending resolver for a subnetwork in a vault.

    \b
    VAULT_ADDRESS - an address of the vault to get a pending resolver for
    NETWORK_ADDRESS - an address of the network to get a pending resolver for
    """
    vault_address = ctx.obj.normalize_address(vault_address)
    network_address = ctx.obj.normalize_address(network_address)

    slasher = ctx.obj.get_slasher(vault_address)
    slasher_type = ctx.obj.get_entity_type(slasher)

    if slasher_type != 1:
        print("It is not a VetoSlasher.")
        return

    print()
    for subnetwork_id in ctx.obj.SUBNETWORKS:
        subnetwork = ctx.obj.get_subnetwork(network_address, subnetwork_id)

        resolver = ctx.obj.get_resolver(slasher, subnetwork)
        pending_resolver = ctx.obj.get_pending_resolver(slasher, subnetwork)

        if resolver == pending_resolver:
            print(
                f"There is no pending resolver for subnetwork = {subnetwork} at vault {vault_address}"
            )
        else:
            print(
                f"Pending resolver for subnetwork = {subnetwork} at vault {vault_address} is {pending_resolver}"
            )
        print()


@cli.command()
@click.argument("vault_address", type=address_type)
@click.argument("resolver", type=address_type)
@click.argument("subnetwork_id", default=0, type=uint96_type)
@click.option(
    "--private-key", type=bytes32_type, help="Your private key for signing transactions"
)
@click.option(
    "--ledger",
    is_flag=True,
    help="Use a Ledger device for signing transactions instead of a private key",
)
@click.option(
    "--ledger-address",
    type=address_type,
    help="The Ledger account address to use for signing (defaults to the first account if not provided)",
)
@click.pass_context
def set_resolver(
    ctx, vault_address, resolver, subnetwork_id, private_key, ledger, ledger_address
):
    """Set a resolver for a subnetwork at VetoSlasher.

    \b
    VAULT_ADDRESS - an address of the vault to set a resolver for
    RESOLVER - an address of the resolver to set
    SUBNETWORK_ID - an identifier of the subnetwork to set a resolver for (default is 0)
    """
    vault_address = ctx.obj.normalize_address(vault_address)
    resolver = ctx.obj.normalize_address(resolver)

    slasher = ctx.obj.get_slasher(vault_address)
    slasher_type = ctx.obj.get_entity_type(slasher)

    if slasher_type != 1:
        print("It is not a VetoSlasher.")
        return

    net = ctx.obj.get_address(private_key, ledger, ledger_address)

    subnetwork = ctx.obj.get_subnetwork(net, subnetwork_id)

    current_resolver = ctx.obj.get_resolver(slasher, subnetwork)
    pending_resolver = ctx.obj.get_pending_resolver(slasher, subnetwork)
    new_timestamp = ctx.obj.get_vault_current_epoch_start(
        vault_address
    ) + ctx.obj.get_resolver_set_epoch_delay(
        slasher
    ) * ctx.obj.get_vault_epoch_duration(
        vault_address
    )
    new_datetime = ctx.obj.timestamp_to_datetime(new_timestamp)

    if current_resolver != pending_resolver:
        if not ctx.obj.process_request(
            f"""You have a pending set resolver request for {pending_resolver}.
Are you sure you want to remove the existing request and create a new one with a new set timestamp = {new_datetime}? (y/n)
"""
        ):
            return

    ctx.obj.process_write_transaction(
        private_key,
        ledger,
        ledger_address,
        "veto_slasher",
        slasher,
        "setResolver",
        subnetwork_id,
        resolver,
        "0x",
        success_message=f"Successfully set resolver = {resolver} for subnetwork = {subnetwork} at vault = {vault_address}",
    )


### OPERATOR CLI COMMANDS ###


@cli.command()
@click.option(
    "--private-key", type=bytes32_type, help="Your private key for signing transactions"
)
@click.option(
    "--ledger",
    is_flag=True,
    help="Use a Ledger device for signing transactions instead of a private key",
)
@click.option(
    "--ledger-address",
    type=address_type,
    help="The Ledger account address to use for signing (defaults to the first account if not provided)",
)
@click.pass_context
def register_operator(ctx, private_key, ledger, ledger_address):
    """Register the signer as an operator."""

    if not private_key and not ledger:
        print("Private key or ledger is required")
        return

    ctx.obj.process_write_transaction(
        private_key,
        ledger,
        ledger_address,
        "op_registry",
        ctx.obj.addresses["op_registry"],
        "registerOperator",
        success_message=f"Successfully registered as an operator",
    )


@cli.command()
@click.argument("vault_address", type=address_type)
@click.option(
    "--private-key", type=bytes32_type, help="Your private key for signing transactions"
)
@click.option(
    "--ledger",
    is_flag=True,
    help="Use a Ledger device for signing transactions instead of a private key",
)
@click.option(
    "--ledger-address",
    type=address_type,
    help="The Ledger account address to use for signing (defaults to the first account if not provided)",
)
@click.pass_context
def opt_in_vault(ctx, vault_address, private_key, ledger, ledger_address):
    """Opt-in to a vault.

    \b
    VAULT_ADDRESS - an address of the vault to opt into
    """
    vault_address = ctx.obj.normalize_address(vault_address)

    ctx.obj.process_write_transaction(
        private_key,
        ledger,
        ledger_address,
        "op_vault_opt_in",
        ctx.obj.addresses["op_vault_opt_in"],
        "optIn",
        vault_address,
        success_message=f"Successfully opted in to vault = {vault_address}",
    )


@cli.command()
@click.argument("vault_address", type=address_type)
@click.argument("duration", default=7 * 24 * 60 * 60, type=uint48_type)
@click.option(
    "--private-key", type=bytes32_type, help="Your private key for signing transactions"
)
@click.option(
    "--ledger",
    is_flag=True,
    help="Use a Ledger device for signing transactions instead of a private key",
)
@click.option(
    "--ledger-address",
    type=address_type,
    help="The Ledger account address to use for signing (defaults to the first account if not provided)",
)
@click.pass_context
def opt_in_vault_signature(
    ctx, vault_address, duration, private_key, ledger, ledger_address
):
    """Get a signature for opt-in to a vault.

    \b
    VAULT_ADDRESS - an address of the vault to opt into
    DURATION - a period of time (in seconds) after which the signature will expire (default is 7 days)
    """
    vault_address = ctx.obj.normalize_address(vault_address)

    ctx.obj.get_operator_vault_opt_in_signature(
        private_key,
        ledger,
        ledger_address,
        vault_address,
        duration,
    )


@cli.command()
@click.argument("vault_address", type=address_type)
@click.option(
    "--private-key", type=bytes32_type, help="Your private key for signing transactions"
)
@click.option(
    "--ledger",
    is_flag=True,
    help="Use a Ledger device for signing transactions instead of a private key",
)
@click.option(
    "--ledger-address",
    type=address_type,
    help="The Ledger account address to use for signing (defaults to the first account if not provided)",
)
@click.pass_context
def opt_out_vault(ctx, vault_address, private_key, ledger, ledger_address):
    """Opt-out from a vault.

    \b
    VAULT_ADDRESS - an address of the vault to opt out from
    """
    vault_address = ctx.obj.normalize_address(vault_address)

    ctx.obj.process_write_transaction(
        private_key,
        ledger,
        ledger_address,
        "op_vault_opt_in",
        ctx.obj.addresses["op_vault_opt_in"],
        "optOut",
        vault_address,
        success_message=f"Successfully opted out from vault = {vault_address}",
    )


@cli.command()
@click.argument("vault_address", type=address_type)
@click.argument("duration", default=7 * 24 * 60 * 60, type=uint48_type)
@click.option(
    "--private-key", type=bytes32_type, help="Your private key for signing transactions"
)
@click.option(
    "--ledger",
    is_flag=True,
    help="Use a Ledger device for signing transactions instead of a private key",
)
@click.option(
    "--ledger-address",
    type=address_type,
    help="The Ledger account address to use for signing (defaults to the first account if not provided)",
)
@click.pass_context
def opt_out_vault_signature(
    ctx, vault_address, duration, private_key, ledger, ledger_address
):
    """Get a signature for opt-out from a vault.

    \b
    VAULT_ADDRESS - an address of the vault to opt out from
    DURATION - a period of time (in seconds) after which the signature will expire (default is 7 days)
    """
    vault_address = ctx.obj.normalize_address(vault_address)

    ctx.obj.get_operator_vault_opt_out_signature(
        private_key,
        ledger,
        ledger_address,
        vault_address,
        duration,
    )


@cli.command()
@click.argument("network_address", type=address_type)
@click.option(
    "--private-key", type=bytes32_type, help="Your private key for signing transactions"
)
@click.option(
    "--ledger",
    is_flag=True,
    help="Use a Ledger device for signing transactions instead of a private key",
)
@click.option(
    "--ledger-address",
    type=address_type,
    help="The Ledger account address to use for signing (defaults to the first account if not provided)",
)
@click.pass_context
def opt_in_network(ctx, network_address, private_key, ledger, ledger_address):
    """Opt-in to a network.

    \b
    NETWORK_ADDRESS - an address of the network to opt into
    """
    network_address = ctx.obj.normalize_address(network_address)

    ctx.obj.process_write_transaction(
        private_key,
        ledger,
        ledger_address,
        "op_net_opt_in",
        ctx.obj.addresses["op_net_opt_in"],
        "optIn",
        network_address,
        success_message=f"Successfully opted in to network = {network_address}",
    )


@cli.command()
@click.argument("network_address", type=address_type)
@click.argument("duration", default=7 * 24 * 60 * 60, type=uint48_type)
@click.option(
    "--private-key", type=bytes32_type, help="Your private key for signing transactions"
)
@click.option(
    "--ledger",
    is_flag=True,
    help="Use a Ledger device for signing transactions instead of a private key",
)
@click.option(
    "--ledger-address",
    type=address_type,
    help="The Ledger account address to use for signing (defaults to the first account if not provided)",
)
@click.pass_context
def opt_in_network_signature(
    ctx, network_address, duration, private_key, ledger, ledger_address
):
    """Get a signature for opt-in to a network.

    \b
    NETWORK_ADDRESS - an address of the network to opt into
    DURATION - a period of time (in seconds) after which the signature will expire (default is 7 days)
    """
    network_address = ctx.obj.normalize_address(network_address)

    ctx.obj.get_operator_network_opt_in_signature(
        private_key,
        ledger,
        ledger_address,
        network_address,
        duration,
    )


@cli.command()
@click.argument("network_address", type=address_type)
@click.option(
    "--private-key", type=bytes32_type, help="Your private key for signing transactions"
)
@click.option(
    "--ledger",
    is_flag=True,
    help="Use a Ledger device for signing transactions instead of a private key",
)
@click.option(
    "--ledger-address",
    type=address_type,
    help="The Ledger account address to use for signing (defaults to the first account if not provided)",
)
@click.pass_context
def opt_out_network(ctx, network_address, private_key, ledger, ledger_address):
    """Opt-out from a network.

    \b
    NETWORK_ADDRESS - an address of the network to opt out from
    """
    network_address = ctx.obj.normalize_address(network_address)

    ctx.obj.process_write_transaction(
        private_key,
        ledger,
        ledger_address,
        "op_net_opt_in",
        ctx.obj.addresses["op_net_opt_in"],
        "optOut",
        network_address,
        success_message=f"Successfully opted out from network = {network_address}",
    )


@cli.command()
@click.argument("network_address", type=address_type)
@click.argument("duration", default=7 * 24 * 60 * 60, type=uint48_type)
@click.option(
    "--private-key", type=bytes32_type, help="Your private key for signing transactions"
)
@click.option(
    "--ledger",
    is_flag=True,
    help="Use a Ledger device for signing transactions instead of a private key",
)
@click.option(
    "--ledger-address",
    type=address_type,
    help="The Ledger account address to use for signing (defaults to the first account if not provided)",
)
@click.pass_context
def opt_out_network_signature(
    ctx, network_address, duration, private_key, ledger, ledger_address
):
    """Get a signature for opt-out from a network.

    \b
    NETWORK_ADDRESS - an address of the network to opt out from
    DURATION - a period of time (in seconds) after which the signature will expire (default is 7 days)
    """
    network_address = ctx.obj.normalize_address(network_address)

    ctx.obj.get_operator_network_opt_out_signature(
        private_key,
        ledger,
        ledger_address,
        network_address,
        duration,
    )


### VAULT CURATOR CLI COMMANDS ###


@cli.command()
@click.argument("vault_address", type=address_type)
@click.argument("network_address", type=address_type)
@click.argument("limit", type=uint256_type)
@click.argument("subnetwork_id", default=0, type=uint96_type)
@click.option(
    "--private-key", type=bytes32_type, help="Your private key for signing transactions"
)
@click.option(
    "--ledger",
    is_flag=True,
    help="Use a Ledger device for signing transactions instead of a private key",
)
@click.option(
    "--ledger-address",
    type=address_type,
    help="The Ledger account address to use for signing (defaults to the first account if not provided)",
)
@click.pass_context
def set_network_limit(
    ctx,
    vault_address,
    network_address,
    limit,
    subnetwork_id,
    private_key,
    ledger,
    ledger_address,
):
    """Set a network limit at the vault's delegator.

    \b
    VAULT_ADDRESS - an address of the vault to adjust the delegations for
    NETWORK_ADDRESS - an address of the network to set a limit for
    LIMIT - a maximum amount of stake the network can get (in wei)
    SUBNETWORK_ID - an identifier of the subnetwork to adjust the delegations for (default is 0)
    """
    vault_address = ctx.obj.normalize_address(vault_address)
    network_address = ctx.obj.normalize_address(network_address)

    subnetwork = ctx.obj.get_subnetwork(network_address, subnetwork_id)

    delegator = ctx.obj.get_delegator(vault_address)
    delegator_type = ctx.obj.get_entity_type(delegator)

    if delegator_type not in [0, 1, 2]:
        print("Delegator doesn't have such functionality.")
        return

    ctx.obj.process_write_transaction(
        private_key,
        ledger,
        ledger_address,
        ctx.obj.DELEGATOR_TYPES_ENTITIES[delegator_type],
        delegator,
        "setNetworkLimit",
        subnetwork,
        limit,
        success_message=f"Successfully set limit = {limit} for subnetwork = {subnetwork}",
    )


@cli.command()
@click.argument("vault_address", type=address_type)
@click.argument("network_address", type=address_type)
@click.pass_context
def network_limit(ctx, vault_address, network_address):
    """Get a current network limit for a subnetwork in a vault.

    \b
    VAULT_ADDRESS - an address of the vault to get a network limit for
    NETWORK_ADDRESS - an address of the network to get a network limit for
    """
    vault_address = ctx.obj.normalize_address(vault_address)
    network_address = ctx.obj.normalize_address(network_address)

    delegator = ctx.obj.get_delegator(vault_address)
    delegator_type = ctx.obj.get_entity_type(delegator)

    if delegator_type not in [0, 1, 2]:
        print("Delegator doesn't have such functionality.")
        return

    print()
    for subnetwork_id in ctx.obj.SUBNETWORKS:
        subnetwork = ctx.obj.get_subnetwork(network_address, subnetwork_id)

        network_limit = ctx.obj.get_network_limit(delegator, subnetwork)
        print(
            f"Network limit for subnetwork = {subnetwork} at vault {vault_address} is {network_limit}"
        )
        print()


@cli.command()
@click.argument("vault_address", type=address_type)
@click.argument("network_address", type=address_type)
@click.argument("operator_address", type=address_type)
@click.argument("limit", type=uint256_type)
@click.argument("subnetwork_id", default=0, type=uint96_type)
@click.option(
    "--private-key", type=bytes32_type, help="Your private key for signing transactions"
)
@click.option(
    "--ledger",
    is_flag=True,
    help="Use a Ledger device for signing transactions instead of a private key",
)
@click.option(
    "--ledger-address",
    type=address_type,
    help="The Ledger account address to use for signing (defaults to the first account if not provided)",
)
@click.pass_context
def set_operator_network_limit(
    ctx,
    vault_address,
    network_address,
    operator_address,
    limit,
    subnetwork_id,
    private_key,
    ledger,
    ledger_address,
):
    """Set an operator-network limit at the vault's delegator.

    \b
    VAULT_ADDRESS - an address of the vault to adjust the delegations for
    NETWORK_ADDRESS - an address of the network
    OPERATOR_ADDRESS - an address of the operator to set a limit in the network for
    LIMIT - a maximum amount of stake the operator can get in the network (in wei)
    SUBNETWORK_ID - an identifier of the subnetwork to adjust the delegations for (default is 0)
    """
    vault_address = ctx.obj.normalize_address(vault_address)
    network_address = ctx.obj.normalize_address(network_address)
    operator_address = ctx.obj.normalize_address(operator_address)

    subnetwork = ctx.obj.get_subnetwork(network_address, subnetwork_id)

    delegator = ctx.obj.get_delegator(vault_address)
    delegator_type = ctx.obj.get_entity_type(delegator)

    if delegator_type != 1:
        print("It is not a FullRestakeDelegator.")
        return

    ctx.obj.process_write_transaction(
        private_key,
        ledger,
        ledger_address,
        ctx.obj.DELEGATOR_TYPES_ENTITIES[delegator_type],
        delegator,
        "setOperatorNetworkLimit",
        subnetwork,
        operator_address,
        limit,
        success_message=f"Successfully set limit = {limit} for operator = {operator_address} in subnetwork = {subnetwork}",
    )


@cli.command()
@click.argument("vault_address", type=address_type)
@click.argument("network_address", type=address_type)
@click.argument("operator_address", type=address_type)
@click.pass_context
def operator_network_limit(ctx, vault_address, network_address, operator_address):
    """Get a current operator-network limit for an operator in the subnetwork.

    \b
    VAULT_ADDRESS - an address of the vault to get a operator-network limit for
    NETWORK_ADDRESS - an address of the network to get a operator-network limit for
    OPERATOR_ADDRESS - an address of the operator to get a operator-network limit for
    """
    vault_address = ctx.obj.normalize_address(vault_address)
    network_address = ctx.obj.normalize_address(network_address)
    operator_address = ctx.obj.normalize_address(operator_address)

    delegator = ctx.obj.get_delegator(vault_address)
    delegator_type = ctx.obj.get_entity_type(delegator)

    if delegator_type != 1:
        print("It is not a FullRestakeDelegator.")
        return

    print()
    for subnetwork_id in ctx.obj.SUBNETWORKS:
        subnetwork = ctx.obj.get_subnetwork(network_address, subnetwork_id)

        operator_network_limit = ctx.obj.get_operator_network_limit(
            delegator, subnetwork, operator_address
        )
        print(
            f"Operator-network limit for subnetwork = {subnetwork} and operator = {operator_address} at vault {vault_address} is {operator_network_limit}"
        )
        print()


@cli.command()
@click.argument("vault_address", type=address_type)
@click.argument("network_address", type=address_type)
@click.argument("operator_address", type=address_type)
@click.argument("shares", type=uint256_type)
@click.argument("subnetwork_id", default=0, type=uint96_type)
@click.option(
    "--private-key", type=bytes32_type, help="Your private key for signing transactions"
)
@click.option(
    "--ledger",
    is_flag=True,
    help="Use a Ledger device for signing transactions instead of a private key",
)
@click.option(
    "--ledger-address",
    type=address_type,
    help="The Ledger account address to use for signing (defaults to the first account if not provided)",
)
@click.pass_context
def set_operator_network_shares(
    ctx,
    vault_address,
    network_address,
    operator_address,
    shares,
    subnetwork_id,
    private_key,
    ledger,
    ledger_address,
):
    """Set an operator-network shares at the vault's delegator.

    \b
    VAULT_ADDRESS - an address of the vault to adjust the delegations for
    NETWORK_ADDRESS - an address of the network
    OPERATOR_ADDRESS - an address of the operator to set shares in the network for
    SHARES - an amount of shares (determines a percent = operator shares / total shares of the network stake the operator can get) to set for the operator
    SUBNETWORK_ID - an identifier of the subnetwork to adjust the delegations for (default is 0)
    """
    vault_address = ctx.obj.normalize_address(vault_address)
    network_address = ctx.obj.normalize_address(network_address)
    operator_address = ctx.obj.normalize_address(operator_address)

    subnetwork = ctx.obj.get_subnetwork(network_address, subnetwork_id)

    delegator = ctx.obj.get_delegator(vault_address)
    delegator_type = ctx.obj.get_entity_type(delegator)

    if delegator_type != 0:
        print("It is not a NetworkRestakeDelegator.")
        return

    operator_network_shares = ctx.obj.get_operator_network_shares(
        delegator, subnetwork, operator_address
    )
    total_operator_network_shares = ctx.obj.get_total_operator_network_shares(
        delegator, subnetwork
    )
    new_total_operator_network_shares = (
        total_operator_network_shares - operator_network_shares + shares
    )

    percentage = (
        0
        if new_total_operator_network_shares == 0
        else shares / new_total_operator_network_shares * 100
    )

    if not ctx.obj.process_request(
        f"Are you sure you want to make operator = {operator_address} to get {percentage}% of the subnetwork = {subnetwork} stake? (y/n)"
    ):
        return

    ctx.obj.process_write_transaction(
        private_key,
        ledger,
        ledger_address,
        ctx.obj.DELEGATOR_TYPES_ENTITIES[delegator_type],
        delegator,
        "setOperatorNetworkShares",
        subnetwork,
        operator_address,
        shares,
        success_message=f"Successfully set shares = {shares} for operator = {operator_address} in subnetwork = {subnetwork}",
    )


@cli.command()
@click.argument("vault_address", type=address_type)
@click.argument("network_address", type=address_type)
@click.argument("operator_address", type=address_type)
@click.pass_context
def operator_network_shares(ctx, vault_address, network_address, operator_address):
    """Get current operator-network shares for an operator in the subnetwork.

    \b
    VAULT_ADDRESS - an address of the vault to get operator-network shares for
    NETWORK_ADDRESS - an address of the network to get operator-network shares for
    OPERATOR_ADDRESS - an address of the operator to get operator-network shares for
    """
    vault_address = ctx.obj.normalize_address(vault_address)
    network_address = ctx.obj.normalize_address(network_address)
    operator_address = ctx.obj.normalize_address(operator_address)

    delegator = ctx.obj.get_delegator(vault_address)
    delegator_type = ctx.obj.get_entity_type(delegator)

    if delegator_type != 0:
        print("It is not a NetworkRestakeDelegator.")
        return

    print()
    for subnetwork_id in ctx.obj.SUBNETWORKS:
        subnetwork = ctx.obj.get_subnetwork(network_address, subnetwork_id)

        operator_network_shares = ctx.obj.get_operator_network_shares(
            delegator, subnetwork, operator_address
        )
        print(
            f"Operator-network shares for subnetwork = {subnetwork} and operator = {operator_address} at vault {vault_address} is {operator_network_shares}"
        )
        print()


@cli.command()
@click.argument("vault_address", type=address_type)
@click.argument("network_address", type=address_type)
@click.pass_context
def total_operator_network_shares(ctx, vault_address, network_address):
    """Get current total operator-network shares for a subnetwork in a vault.

    \b
    VAULT_ADDRESS - an address of the vault to get total operator-network shares for
    NETWORK_ADDRESS - an address of the network to get total operator-network shares for
    """
    vault_address = ctx.obj.normalize_address(vault_address)
    network_address = ctx.obj.normalize_address(network_address)

    delegator = ctx.obj.get_delegator(vault_address)
    delegator_type = ctx.obj.get_entity_type(delegator)

    if delegator_type != 0:
        print("It is not a NetworkRestakeDelegator.")
        return

    print()
    for subnetwork_id in ctx.obj.SUBNETWORKS:
        subnetwork = ctx.obj.get_subnetwork(network_address, subnetwork_id)

        total_operator_network_shares = ctx.obj.get_total_operator_network_shares(
            delegator, subnetwork
        )
        print(
            f"Total operator-network shares for subnetwork = {subnetwork} at vault {vault_address} is {total_operator_network_shares}"
        )
        print()


### STAKER CLI COMMANDS ###


@cli.command()
@click.argument("vault_address", type=address_type)
@click.argument("amount", type=token_amount_type)
@click.argument(
    "on_behalf_of",
    default="0x0000000000000000000000000000000000000000",
    type=address_type,
)
@click.option(
    "--private-key", type=bytes32_type, help="Your private key for signing transactions"
)
@click.option(
    "--ledger",
    is_flag=True,
    help="Use a Ledger device for signing transactions instead of a private key",
)
@click.option(
    "--ledger-address",
    type=address_type,
    help="The Ledger account address to use for signing (defaults to the first account if not provided)",
)
@click.pass_context
def deposit(
    ctx,
    vault_address,
    amount,
    on_behalf_of,
    private_key,
    ledger,
    ledger_address,
):
    """Deposit to the vault.

    \b
    VAULT_ADDRESS - an address of the vault to deposit to
    AMOUNT - an amount of tokens to deposit (in the token value, e.g., 1000 for 1000 ETH)
    ON_BEHALF_OF - an address to make a deposit on behalf of (default: address of the signer)
    """
    vault_address = ctx.obj.normalize_address(vault_address)
    signer = ctx.obj.get_address(private_key, ledger, ledger_address)
    on_behalf_of = ctx.obj.normalize_address(on_behalf_of)
    if on_behalf_of == "0x0000000000000000000000000000000000000000":
        on_behalf_of = signer
    token_address = ctx.obj.get_collateral(vault_address)
    wei_amount = ctx.obj.get_wei_amount(token_address, amount)
    symbol = ctx.obj.get_token_meta(token_address)["symbol"]

    if on_behalf_of != signer:
        if not ctx.obj.process_request(
            f"Are you sure you want to deposit {amount} {symbol} to vault = {vault_address} on behalf of {on_behalf_of}? (y/n)"
        ):
            return

    allowance = ctx.obj.get_allowance(token_address, signer, vault_address)

    if allowance < wei_amount:
        print("Need to approve the vault to spend the tokens")
        ctx.obj.process_write_transaction(
            private_key,
            ledger,
            ledger_address,
            "erc20",
            token_address,
            "approve",
            vault_address,
            wei_amount,
            success_message=f"Successfully approved {amount} {symbol} for deposit to vault = {vault_address}",
        )

    print("Depositing...")
    ctx.obj.process_write_transaction(
        private_key,
        ledger,
        ledger_address,
        "vault",
        vault_address,
        "deposit",
        on_behalf_of,
        wei_amount,
        success_message=f"Successfully deposited {amount} {symbol} to vault = {vault_address} on behalf of {on_behalf_of}",
    )


@cli.command()
@click.argument("vault_address", type=address_type)
@click.argument("amount", type=token_amount_type)
@click.argument(
    "claimer",
    default="0x0000000000000000000000000000000000000000",
    type=address_type,
)
@click.option(
    "--private-key", type=bytes32_type, help="Your private key for signing transactions"
)
@click.option(
    "--ledger",
    is_flag=True,
    help="Use a Ledger device for signing transactions instead of a private key",
)
@click.option(
    "--ledger-address",
    type=address_type,
    help="The Ledger account address to use for signing (defaults to the first account if not provided)",
)
@click.pass_context
def withdraw(
    ctx,
    vault_address,
    amount,
    claimer,
    private_key,
    ledger,
    ledger_address,
):
    """Withdraw from the vault.

    \b
    VAULT_ADDRESS - an address of the vault to withdraw from
    AMOUNT - an amount of tokens to withdraw (in the token value, e.g., 1000 for 1000 ETH)
    CLAIMER - an address that needs to claim the withdrawal (default: address of the signer)
    """
    vault_address = ctx.obj.normalize_address(vault_address)
    signer = ctx.obj.get_address(private_key, ledger, ledger_address)
    claimer = ctx.obj.normalize_address(claimer)
    if claimer == "0x0000000000000000000000000000000000000000":
        claimer = signer
    token_address = ctx.obj.get_collateral(vault_address)
    wei_amount = ctx.obj.get_wei_amount(token_address, amount)
    symbol = ctx.obj.get_token_meta(token_address)["symbol"]

    if claimer != signer:
        if not ctx.obj.process_request(
            f"Are you sure you want to withdraw {amount} {symbol} from vault = {vault_address} with claimer = {claimer}? (y/n)"
        ):
            return

    epoch_duration = ctx.obj.get_vault_epoch_duration(vault_address)
    current_epoch = ctx.obj.get_vault_current_epoch(vault_address)
    current_epoch_start = ctx.obj.get_vault_current_epoch_start(vault_address)

    next_epoch = current_epoch + 1
    next_epoch_end = current_epoch_start + 2 * epoch_duration

    ctx.obj.process_write_transaction(
        private_key,
        ledger,
        ledger_address,
        "vault",
        vault_address,
        "withdraw",
        claimer,
        wei_amount,
        success_message=f"""Successfully withdrew {amount} {symbol} from vault = {vault_address} with claimer = {claimer}
It will be claimable after epoch {next_epoch} ends ({ctx.obj.timestamp_to_datetime(next_epoch_end)})""",
    )


@cli.command()
@click.argument("vault_address", type=address_type)
@click.argument("epoch", type=uint256_type)
@click.argument(
    "recipient",
    default="0x0000000000000000000000000000000000000000",
    type=address_type,
)
@click.option(
    "--private-key", type=bytes32_type, help="Your private key for signing transactions"
)
@click.option(
    "--ledger",
    is_flag=True,
    help="Use a Ledger device for signing transactions instead of a private key",
)
@click.option(
    "--ledger-address",
    type=address_type,
    help="The Ledger account address to use for signing (defaults to the first account if not provided)",
)
@click.pass_context
def claim(
    ctx,
    vault_address,
    epoch,
    recipient,
    private_key,
    ledger,
    ledger_address,
):
    """Claim a withdrawal for some epoch at the vault.

    \b
    VAULT_ADDRESS - an address of the vault to claim from
    EPOCH - an epoch number to claim a withdrawal for
    RECIPIENT - an address that will receive the tokens (default: address of the signer)
    """
    vault_address = ctx.obj.normalize_address(vault_address)
    signer = ctx.obj.get_address(private_key, ledger, ledger_address)
    recipient = ctx.obj.normalize_address(recipient)
    if recipient == "0x0000000000000000000000000000000000000000":
        recipient = signer

    current_epoch = ctx.obj.get_vault_current_epoch(vault_address)
    if epoch >= current_epoch:
        print(f"Epoch {epoch} isn't claimable yet")
        return

    withdrawals_wei = ctx.obj.get_withdrawals(vault_address, epoch, signer)
    if withdrawals_wei == 0:
        print(f"No withdrawals for epoch {epoch}")
        return

    withdrawals_claimed = ctx.obj.get_withdrawals_claimed(vault_address, epoch, signer)
    if withdrawals_claimed:
        print(f"Already claimed withdrawals for epoch {epoch}")
        return

    token_address = ctx.obj.get_collateral(vault_address)
    symbol = ctx.obj.get_token_meta(token_address)["symbol"]
    withdrawals = ctx.obj.get_token_amount(token_address, withdrawals_wei)
    if recipient != signer:
        if not ctx.obj.process_request(
            f"Are you sure you want to claim {withdrawals} {symbol} from vault = {vault_address} to recipient = {recipient}? (y/n)"
        ):
            return

    ctx.obj.process_write_transaction(
        private_key,
        ledger,
        ledger_address,
        "vault",
        vault_address,
        "claim",
        recipient,
        epoch,
        success_message=f"""Successfully claimed {withdrawals} {symbol} from vault = {vault_address} to recipient = {recipient} for epoch = {epoch}""",
    )


if __name__ == "__main__":
    cli()
