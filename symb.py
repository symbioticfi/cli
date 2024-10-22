import warnings

warnings.filterwarnings("ignore", category=UserWarning, module="eth_utils")

import click
from web3 import Web3
from w3multicall.multicall import W3Multicall
import ledgereth
from eth_account import Account
from datetime import datetime
import re
from decimal import Decimal, InvalidOperation


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


address_type = AddressType()
bytes32_type = Bytes32Type()
uint256_type = Uint256Type()
uint96_type = Uint96Type()
uint48_type = Uint48Type()
token_amount_type = TokenAmountType()


class SymbioticCLI:

    ABIS = {
        "op_registry": '[{"inputs":[],"name":"EntityNotExist","type":"error"},{"inputs":[],"name":"OperatorAlreadyRegistered","type":"error"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"entity","type":"address"}],"name":"AddEntity","type":"event"},{"inputs":[{"internalType":"uint256","name":"index","type":"uint256"}],"name":"entity","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"entity_","type":"address"}],"name":"isEntity","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"registerOperator","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"totalEntities","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"}]',
        "net_registry": '[{"inputs":[],"name":"EntityNotExist","type":"error"},{"inputs":[],"name":"NetworkAlreadyRegistered","type":"error"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"entity","type":"address"}],"name":"AddEntity","type":"event"},{"inputs":[{"internalType":"uint256","name":"index","type":"uint256"}],"name":"entity","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"entity_","type":"address"}],"name":"isEntity","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"registerNetwork","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"totalEntities","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"}]',
        "op_vault_opt_in": '[{"inputs":[{"internalType":"address","name":"whoRegistry","type":"address"},{"internalType":"address","name":"whereRegistry","type":"address"}],"stateMutability":"nonpayable","type":"constructor"},{"inputs":[],"name":"AlreadyOptedIn","type":"error"},{"inputs":[],"name":"CheckpointUnorderedInsertion","type":"error"},{"inputs":[],"name":"NotOptedIn","type":"error"},{"inputs":[],"name":"NotWhereEntity","type":"error"},{"inputs":[],"name":"NotWho","type":"error"},{"inputs":[],"name":"OptOutCooldown","type":"error"},{"inputs":[{"internalType":"uint8","name":"bits","type":"uint8"},{"internalType":"uint256","name":"value","type":"uint256"}],"name":"SafeCastOverflowedUintDowncast","type":"error"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"who","type":"address"},{"indexed":true,"internalType":"address","name":"where","type":"address"}],"name":"OptIn","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"who","type":"address"},{"indexed":true,"internalType":"address","name":"where","type":"address"}],"name":"OptOut","type":"event"},{"inputs":[],"name":"WHERE_REGISTRY","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"WHO_REGISTRY","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"who","type":"address"},{"internalType":"address","name":"where","type":"address"}],"name":"isOptedIn","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"who","type":"address"},{"internalType":"address","name":"where","type":"address"},{"internalType":"uint48","name":"timestamp","type":"uint48"},{"internalType":"bytes","name":"hint","type":"bytes"}],"name":"isOptedInAt","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"where","type":"address"}],"name":"optIn","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"where","type":"address"}],"name":"optOut","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"target","type":"address"},{"internalType":"bytes","name":"data","type":"bytes"}],"name":"staticDelegateCall","outputs":[],"stateMutability":"nonpayable","type":"function"}]',
        "op_net_opt_in": '[{"inputs":[{"internalType":"address","name":"whoRegistry","type":"address"},{"internalType":"address","name":"whereRegistry","type":"address"}],"stateMutability":"nonpayable","type":"constructor"},{"inputs":[],"name":"AlreadyOptedIn","type":"error"},{"inputs":[],"name":"CheckpointUnorderedInsertion","type":"error"},{"inputs":[],"name":"NotOptedIn","type":"error"},{"inputs":[],"name":"NotWhereEntity","type":"error"},{"inputs":[],"name":"NotWho","type":"error"},{"inputs":[],"name":"OptOutCooldown","type":"error"},{"inputs":[{"internalType":"uint8","name":"bits","type":"uint8"},{"internalType":"uint256","name":"value","type":"uint256"}],"name":"SafeCastOverflowedUintDowncast","type":"error"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"who","type":"address"},{"indexed":true,"internalType":"address","name":"where","type":"address"}],"name":"OptIn","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"who","type":"address"},{"indexed":true,"internalType":"address","name":"where","type":"address"}],"name":"OptOut","type":"event"},{"inputs":[],"name":"WHERE_REGISTRY","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"WHO_REGISTRY","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"who","type":"address"},{"internalType":"address","name":"where","type":"address"}],"name":"isOptedIn","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"who","type":"address"},{"internalType":"address","name":"where","type":"address"},{"internalType":"uint48","name":"timestamp","type":"uint48"},{"internalType":"bytes","name":"hint","type":"bytes"}],"name":"isOptedInAt","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"where","type":"address"}],"name":"optIn","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"where","type":"address"}],"name":"optOut","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"target","type":"address"},{"internalType":"bytes","name":"data","type":"bytes"}],"name":"staticDelegateCall","outputs":[],"stateMutability":"nonpayable","type":"function"}]',
        "middleware_service": '[{"inputs":[{"internalType":"address","name":"networkRegistry","type":"address"}],"stateMutability":"nonpayable","type":"constructor"},{"inputs":[],"name":"AlreadySet","type":"error"},{"inputs":[],"name":"NotNetwork","type":"error"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"network","type":"address"},{"indexed":false,"internalType":"address","name":"middleware","type":"address"}],"name":"SetMiddleware","type":"event"},{"inputs":[],"name":"NETWORK_REGISTRY","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"network","type":"address"}],"name":"middleware","outputs":[{"internalType":"address","name":"value","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"middleware_","type":"address"}],"name":"setMiddleware","outputs":[],"stateMutability":"nonpayable","type":"function"}]',
        "vault_factory": '[{"inputs":[{"internalType":"address","name":"owner_","type":"address"}],"stateMutability":"nonpayable","type":"constructor"},{"inputs":[],"name":"AlreadyWhitelisted","type":"error"},{"inputs":[],"name":"EntityNotExist","type":"error"},{"inputs":[],"name":"InvalidImplementation","type":"error"},{"inputs":[],"name":"InvalidVersion","type":"error"},{"inputs":[],"name":"NotOwner","type":"error"},{"inputs":[],"name":"OldVersion","type":"error"},{"inputs":[{"internalType":"address","name":"owner","type":"address"}],"name":"OwnableInvalidOwner","type":"error"},{"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"OwnableUnauthorizedAccount","type":"error"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"entity","type":"address"}],"name":"AddEntity","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"entity","type":"address"},{"indexed":false,"internalType":"uint64","name":"newVersion","type":"uint64"}],"name":"Migrate","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"previousOwner","type":"address"},{"indexed":true,"internalType":"address","name":"newOwner","type":"address"}],"name":"OwnershipTransferred","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"implementation","type":"address"}],"name":"Whitelist","type":"event"},{"inputs":[{"internalType":"uint64","name":"version","type":"uint64"},{"internalType":"address","name":"owner_","type":"address"},{"internalType":"bool","name":"withInitialize","type":"bool"},{"internalType":"bytes","name":"data","type":"bytes"}],"name":"create","outputs":[{"internalType":"address","name":"entity_","type":"address"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint256","name":"index","type":"uint256"}],"name":"entity","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint64","name":"version","type":"uint64"}],"name":"implementation","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"entity_","type":"address"}],"name":"isEntity","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"lastVersion","outputs":[{"internalType":"uint64","name":"","type":"uint64"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"entity_","type":"address"},{"internalType":"uint64","name":"newVersion","type":"uint64"},{"internalType":"bytes","name":"data","type":"bytes"}],"name":"migrate","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"owner","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"renounceOwnership","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"totalEntities","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"newOwner","type":"address"}],"name":"transferOwnership","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"implementation_","type":"address"}],"name":"whitelist","outputs":[],"stateMutability":"nonpayable","type":"function"}]',
        "entity": '[{"inputs":[{"internalType":"address","name":"networkRegistry","type":"address"},{"internalType":"address","name":"vaultFactory","type":"address"},{"internalType":"address","name":"operatorVaultOptInService","type":"address"},{"internalType":"address","name":"operatorNetworkOptInService","type":"address"},{"internalType":"address","name":"delegatorFactory","type":"address"},{"internalType":"uint64","name":"entityType","type":"uint64"}],"stateMutability":"nonpayable","type":"constructor"},{"inputs":[],"name":"AccessControlBadConfirmation","type":"error"},{"inputs":[{"internalType":"address","name":"account","type":"address"},{"internalType":"bytes32","name":"neededRole","type":"bytes32"}],"name":"AccessControlUnauthorizedAccount","type":"error"},{"inputs":[],"name":"AlreadySet","type":"error"},{"inputs":[],"name":"CheckpointUnorderedInsertion","type":"error"},{"inputs":[],"name":"DuplicateRoleHolder","type":"error"},{"inputs":[],"name":"ExceedsMaxNetworkLimit","type":"error"},{"inputs":[],"name":"InvalidInitialization","type":"error"},{"inputs":[],"name":"MathOverflowedMulDiv","type":"error"},{"inputs":[],"name":"MissingRoleHolders","type":"error"},{"inputs":[],"name":"NotInitializing","type":"error"},{"inputs":[],"name":"NotNetwork","type":"error"},{"inputs":[],"name":"NotSlasher","type":"error"},{"inputs":[],"name":"NotVault","type":"error"},{"inputs":[{"internalType":"uint8","name":"bits","type":"uint8"},{"internalType":"uint256","name":"value","type":"uint256"}],"name":"SafeCastOverflowedUintDowncast","type":"error"},{"inputs":[],"name":"ZeroAddressRoleHolder","type":"error"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"uint64","name":"version","type":"uint64"}],"name":"Initialized","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"subnetwork","type":"bytes32"},{"indexed":true,"internalType":"address","name":"operator","type":"address"},{"indexed":false,"internalType":"uint256","name":"slashedAmount","type":"uint256"}],"name":"OnSlash","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"role","type":"bytes32"},{"indexed":true,"internalType":"bytes32","name":"previousAdminRole","type":"bytes32"},{"indexed":true,"internalType":"bytes32","name":"newAdminRole","type":"bytes32"}],"name":"RoleAdminChanged","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"role","type":"bytes32"},{"indexed":true,"internalType":"address","name":"account","type":"address"},{"indexed":true,"internalType":"address","name":"sender","type":"address"}],"name":"RoleGranted","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"role","type":"bytes32"},{"indexed":true,"internalType":"address","name":"account","type":"address"},{"indexed":true,"internalType":"address","name":"sender","type":"address"}],"name":"RoleRevoked","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"hook","type":"address"}],"name":"SetHook","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"subnetwork","type":"bytes32"},{"indexed":false,"internalType":"uint256","name":"amount","type":"uint256"}],"name":"SetMaxNetworkLimit","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"subnetwork","type":"bytes32"},{"indexed":false,"internalType":"uint256","name":"amount","type":"uint256"}],"name":"SetNetworkLimit","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"subnetwork","type":"bytes32"},{"indexed":true,"internalType":"address","name":"operator","type":"address"},{"indexed":false,"internalType":"uint256","name":"shares","type":"uint256"}],"name":"SetOperatorNetworkShares","type":"event"},{"inputs":[],"name":"DEFAULT_ADMIN_ROLE","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"FACTORY","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"HOOK_SET_ROLE","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"NETWORK_LIMIT_SET_ROLE","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"NETWORK_REGISTRY","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"OPERATOR_NETWORK_OPT_IN_SERVICE","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"OPERATOR_NETWORK_SHARES_SET_ROLE","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"OPERATOR_VAULT_OPT_IN_SERVICE","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"TYPE","outputs":[{"internalType":"uint64","name":"","type":"uint64"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"VAULT_FACTORY","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"VERSION","outputs":[{"internalType":"uint64","name":"","type":"uint64"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"role","type":"bytes32"}],"name":"getRoleAdmin","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"role","type":"bytes32"},{"internalType":"address","name":"account","type":"address"}],"name":"grantRole","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"role","type":"bytes32"},{"internalType":"address","name":"account","type":"address"}],"name":"hasRole","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"hook","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes","name":"data","type":"bytes"}],"name":"initialize","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"subnetwork","type":"bytes32"}],"name":"maxNetworkLimit","outputs":[{"internalType":"uint256","name":"value","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"subnetwork","type":"bytes32"}],"name":"networkLimit","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"subnetwork","type":"bytes32"},{"internalType":"uint48","name":"timestamp","type":"uint48"},{"internalType":"bytes","name":"hint","type":"bytes"}],"name":"networkLimitAt","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"subnetwork","type":"bytes32"},{"internalType":"address","name":"operator","type":"address"},{"internalType":"uint256","name":"slashedAmount","type":"uint256"},{"internalType":"uint48","name":"captureTimestamp","type":"uint48"},{"internalType":"bytes","name":"data","type":"bytes"}],"name":"onSlash","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"subnetwork","type":"bytes32"},{"internalType":"address","name":"operator","type":"address"}],"name":"operatorNetworkShares","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"subnetwork","type":"bytes32"},{"internalType":"address","name":"operator","type":"address"},{"internalType":"uint48","name":"timestamp","type":"uint48"},{"internalType":"bytes","name":"hint","type":"bytes"}],"name":"operatorNetworkSharesAt","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"role","type":"bytes32"},{"internalType":"address","name":"callerConfirmation","type":"address"}],"name":"renounceRole","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"role","type":"bytes32"},{"internalType":"address","name":"account","type":"address"}],"name":"revokeRole","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"hook_","type":"address"}],"name":"setHook","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint96","name":"identifier","type":"uint96"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"setMaxNetworkLimit","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"subnetwork","type":"bytes32"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"setNetworkLimit","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"subnetwork","type":"bytes32"},{"internalType":"address","name":"operator","type":"address"},{"internalType":"uint256","name":"shares","type":"uint256"}],"name":"setOperatorNetworkShares","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"subnetwork","type":"bytes32"},{"internalType":"address","name":"operator","type":"address"}],"name":"stake","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"subnetwork","type":"bytes32"},{"internalType":"address","name":"operator","type":"address"},{"internalType":"uint48","name":"timestamp","type":"uint48"},{"internalType":"bytes","name":"hints","type":"bytes"}],"name":"stakeAt","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"target","type":"address"},{"internalType":"bytes","name":"data","type":"bytes"}],"name":"staticDelegateCall","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes4","name":"interfaceId","type":"bytes4"}],"name":"supportsInterface","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"subnetwork","type":"bytes32"}],"name":"totalOperatorNetworkShares","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"subnetwork","type":"bytes32"},{"internalType":"uint48","name":"timestamp","type":"uint48"},{"internalType":"bytes","name":"hint","type":"bytes"}],"name":"totalOperatorNetworkSharesAt","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"vault","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"}]',
        "delegator": '[{"inputs":[{"internalType":"address","name":"networkRegistry","type":"address"},{"internalType":"address","name":"vaultFactory","type":"address"},{"internalType":"address","name":"operatorVaultOptInService","type":"address"},{"internalType":"address","name":"operatorNetworkOptInService","type":"address"},{"internalType":"address","name":"delegatorFactory","type":"address"},{"internalType":"uint64","name":"entityType","type":"uint64"}],"stateMutability":"nonpayable","type":"constructor"},{"inputs":[],"name":"AccessControlBadConfirmation","type":"error"},{"inputs":[{"internalType":"address","name":"account","type":"address"},{"internalType":"bytes32","name":"neededRole","type":"bytes32"}],"name":"AccessControlUnauthorizedAccount","type":"error"},{"inputs":[],"name":"AlreadySet","type":"error"},{"inputs":[],"name":"CheckpointUnorderedInsertion","type":"error"},{"inputs":[],"name":"DuplicateRoleHolder","type":"error"},{"inputs":[],"name":"ExceedsMaxNetworkLimit","type":"error"},{"inputs":[],"name":"InvalidInitialization","type":"error"},{"inputs":[],"name":"MathOverflowedMulDiv","type":"error"},{"inputs":[],"name":"MissingRoleHolders","type":"error"},{"inputs":[],"name":"NotInitializing","type":"error"},{"inputs":[],"name":"NotNetwork","type":"error"},{"inputs":[],"name":"NotSlasher","type":"error"},{"inputs":[],"name":"NotVault","type":"error"},{"inputs":[{"internalType":"uint8","name":"bits","type":"uint8"},{"internalType":"uint256","name":"value","type":"uint256"}],"name":"SafeCastOverflowedUintDowncast","type":"error"},{"inputs":[],"name":"ZeroAddressRoleHolder","type":"error"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"uint64","name":"version","type":"uint64"}],"name":"Initialized","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"subnetwork","type":"bytes32"},{"indexed":true,"internalType":"address","name":"operator","type":"address"},{"indexed":false,"internalType":"uint256","name":"slashedAmount","type":"uint256"}],"name":"OnSlash","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"role","type":"bytes32"},{"indexed":true,"internalType":"bytes32","name":"previousAdminRole","type":"bytes32"},{"indexed":true,"internalType":"bytes32","name":"newAdminRole","type":"bytes32"}],"name":"RoleAdminChanged","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"role","type":"bytes32"},{"indexed":true,"internalType":"address","name":"account","type":"address"},{"indexed":true,"internalType":"address","name":"sender","type":"address"}],"name":"RoleGranted","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"role","type":"bytes32"},{"indexed":true,"internalType":"address","name":"account","type":"address"},{"indexed":true,"internalType":"address","name":"sender","type":"address"}],"name":"RoleRevoked","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"hook","type":"address"}],"name":"SetHook","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"subnetwork","type":"bytes32"},{"indexed":false,"internalType":"uint256","name":"amount","type":"uint256"}],"name":"SetMaxNetworkLimit","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"subnetwork","type":"bytes32"},{"indexed":false,"internalType":"uint256","name":"amount","type":"uint256"}],"name":"SetNetworkLimit","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"subnetwork","type":"bytes32"},{"indexed":true,"internalType":"address","name":"operator","type":"address"},{"indexed":false,"internalType":"uint256","name":"shares","type":"uint256"}],"name":"SetOperatorNetworkShares","type":"event"},{"inputs":[],"name":"DEFAULT_ADMIN_ROLE","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"FACTORY","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"HOOK_SET_ROLE","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"NETWORK_LIMIT_SET_ROLE","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"NETWORK_REGISTRY","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"OPERATOR_NETWORK_OPT_IN_SERVICE","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"OPERATOR_NETWORK_SHARES_SET_ROLE","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"OPERATOR_VAULT_OPT_IN_SERVICE","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"TYPE","outputs":[{"internalType":"uint64","name":"","type":"uint64"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"VAULT_FACTORY","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"VERSION","outputs":[{"internalType":"uint64","name":"","type":"uint64"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"role","type":"bytes32"}],"name":"getRoleAdmin","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"role","type":"bytes32"},{"internalType":"address","name":"account","type":"address"}],"name":"grantRole","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"role","type":"bytes32"},{"internalType":"address","name":"account","type":"address"}],"name":"hasRole","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"hook","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes","name":"data","type":"bytes"}],"name":"initialize","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"subnetwork","type":"bytes32"}],"name":"maxNetworkLimit","outputs":[{"internalType":"uint256","name":"value","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"subnetwork","type":"bytes32"}],"name":"networkLimit","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"subnetwork","type":"bytes32"},{"internalType":"uint48","name":"timestamp","type":"uint48"},{"internalType":"bytes","name":"hint","type":"bytes"}],"name":"networkLimitAt","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"subnetwork","type":"bytes32"},{"internalType":"address","name":"operator","type":"address"},{"internalType":"uint256","name":"slashedAmount","type":"uint256"},{"internalType":"uint48","name":"captureTimestamp","type":"uint48"},{"internalType":"bytes","name":"data","type":"bytes"}],"name":"onSlash","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"subnetwork","type":"bytes32"},{"internalType":"address","name":"operator","type":"address"}],"name":"operatorNetworkShares","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"subnetwork","type":"bytes32"},{"internalType":"address","name":"operator","type":"address"},{"internalType":"uint48","name":"timestamp","type":"uint48"},{"internalType":"bytes","name":"hint","type":"bytes"}],"name":"operatorNetworkSharesAt","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"role","type":"bytes32"},{"internalType":"address","name":"callerConfirmation","type":"address"}],"name":"renounceRole","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"role","type":"bytes32"},{"internalType":"address","name":"account","type":"address"}],"name":"revokeRole","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"hook_","type":"address"}],"name":"setHook","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint96","name":"identifier","type":"uint96"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"setMaxNetworkLimit","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"subnetwork","type":"bytes32"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"setNetworkLimit","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"subnetwork","type":"bytes32"},{"internalType":"address","name":"operator","type":"address"},{"internalType":"uint256","name":"shares","type":"uint256"}],"name":"setOperatorNetworkShares","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"subnetwork","type":"bytes32"},{"internalType":"address","name":"operator","type":"address"}],"name":"stake","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"subnetwork","type":"bytes32"},{"internalType":"address","name":"operator","type":"address"},{"internalType":"uint48","name":"timestamp","type":"uint48"},{"internalType":"bytes","name":"hints","type":"bytes"}],"name":"stakeAt","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"target","type":"address"},{"internalType":"bytes","name":"data","type":"bytes"}],"name":"staticDelegateCall","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes4","name":"interfaceId","type":"bytes4"}],"name":"supportsInterface","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"subnetwork","type":"bytes32"}],"name":"totalOperatorNetworkShares","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"subnetwork","type":"bytes32"},{"internalType":"uint48","name":"timestamp","type":"uint48"},{"internalType":"bytes","name":"hint","type":"bytes"}],"name":"totalOperatorNetworkSharesAt","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"vault","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"}]',
        "network_restake_delegator": '[{"inputs":[{"internalType":"address","name":"networkRegistry","type":"address"},{"internalType":"address","name":"vaultFactory","type":"address"},{"internalType":"address","name":"operatorVaultOptInService","type":"address"},{"internalType":"address","name":"operatorNetworkOptInService","type":"address"},{"internalType":"address","name":"delegatorFactory","type":"address"},{"internalType":"uint64","name":"entityType","type":"uint64"}],"stateMutability":"nonpayable","type":"constructor"},{"inputs":[],"name":"AccessControlBadConfirmation","type":"error"},{"inputs":[{"internalType":"address","name":"account","type":"address"},{"internalType":"bytes32","name":"neededRole","type":"bytes32"}],"name":"AccessControlUnauthorizedAccount","type":"error"},{"inputs":[],"name":"AlreadySet","type":"error"},{"inputs":[],"name":"CheckpointUnorderedInsertion","type":"error"},{"inputs":[],"name":"DuplicateRoleHolder","type":"error"},{"inputs":[],"name":"ExceedsMaxNetworkLimit","type":"error"},{"inputs":[],"name":"InvalidInitialization","type":"error"},{"inputs":[],"name":"MathOverflowedMulDiv","type":"error"},{"inputs":[],"name":"MissingRoleHolders","type":"error"},{"inputs":[],"name":"NotInitializing","type":"error"},{"inputs":[],"name":"NotNetwork","type":"error"},{"inputs":[],"name":"NotSlasher","type":"error"},{"inputs":[],"name":"NotVault","type":"error"},{"inputs":[{"internalType":"uint8","name":"bits","type":"uint8"},{"internalType":"uint256","name":"value","type":"uint256"}],"name":"SafeCastOverflowedUintDowncast","type":"error"},{"inputs":[],"name":"ZeroAddressRoleHolder","type":"error"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"uint64","name":"version","type":"uint64"}],"name":"Initialized","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"subnetwork","type":"bytes32"},{"indexed":true,"internalType":"address","name":"operator","type":"address"},{"indexed":false,"internalType":"uint256","name":"slashedAmount","type":"uint256"}],"name":"OnSlash","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"role","type":"bytes32"},{"indexed":true,"internalType":"bytes32","name":"previousAdminRole","type":"bytes32"},{"indexed":true,"internalType":"bytes32","name":"newAdminRole","type":"bytes32"}],"name":"RoleAdminChanged","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"role","type":"bytes32"},{"indexed":true,"internalType":"address","name":"account","type":"address"},{"indexed":true,"internalType":"address","name":"sender","type":"address"}],"name":"RoleGranted","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"role","type":"bytes32"},{"indexed":true,"internalType":"address","name":"account","type":"address"},{"indexed":true,"internalType":"address","name":"sender","type":"address"}],"name":"RoleRevoked","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"hook","type":"address"}],"name":"SetHook","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"subnetwork","type":"bytes32"},{"indexed":false,"internalType":"uint256","name":"amount","type":"uint256"}],"name":"SetMaxNetworkLimit","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"subnetwork","type":"bytes32"},{"indexed":false,"internalType":"uint256","name":"amount","type":"uint256"}],"name":"SetNetworkLimit","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"subnetwork","type":"bytes32"},{"indexed":true,"internalType":"address","name":"operator","type":"address"},{"indexed":false,"internalType":"uint256","name":"shares","type":"uint256"}],"name":"SetOperatorNetworkShares","type":"event"},{"inputs":[],"name":"DEFAULT_ADMIN_ROLE","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"FACTORY","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"HOOK_SET_ROLE","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"NETWORK_LIMIT_SET_ROLE","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"NETWORK_REGISTRY","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"OPERATOR_NETWORK_OPT_IN_SERVICE","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"OPERATOR_NETWORK_SHARES_SET_ROLE","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"OPERATOR_VAULT_OPT_IN_SERVICE","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"TYPE","outputs":[{"internalType":"uint64","name":"","type":"uint64"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"VAULT_FACTORY","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"VERSION","outputs":[{"internalType":"uint64","name":"","type":"uint64"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"role","type":"bytes32"}],"name":"getRoleAdmin","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"role","type":"bytes32"},{"internalType":"address","name":"account","type":"address"}],"name":"grantRole","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"role","type":"bytes32"},{"internalType":"address","name":"account","type":"address"}],"name":"hasRole","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"hook","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes","name":"data","type":"bytes"}],"name":"initialize","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"subnetwork","type":"bytes32"}],"name":"maxNetworkLimit","outputs":[{"internalType":"uint256","name":"value","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"subnetwork","type":"bytes32"}],"name":"networkLimit","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"subnetwork","type":"bytes32"},{"internalType":"uint48","name":"timestamp","type":"uint48"},{"internalType":"bytes","name":"hint","type":"bytes"}],"name":"networkLimitAt","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"subnetwork","type":"bytes32"},{"internalType":"address","name":"operator","type":"address"},{"internalType":"uint256","name":"slashedAmount","type":"uint256"},{"internalType":"uint48","name":"captureTimestamp","type":"uint48"},{"internalType":"bytes","name":"data","type":"bytes"}],"name":"onSlash","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"subnetwork","type":"bytes32"},{"internalType":"address","name":"operator","type":"address"}],"name":"operatorNetworkShares","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"subnetwork","type":"bytes32"},{"internalType":"address","name":"operator","type":"address"},{"internalType":"uint48","name":"timestamp","type":"uint48"},{"internalType":"bytes","name":"hint","type":"bytes"}],"name":"operatorNetworkSharesAt","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"role","type":"bytes32"},{"internalType":"address","name":"callerConfirmation","type":"address"}],"name":"renounceRole","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"role","type":"bytes32"},{"internalType":"address","name":"account","type":"address"}],"name":"revokeRole","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"hook_","type":"address"}],"name":"setHook","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint96","name":"identifier","type":"uint96"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"setMaxNetworkLimit","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"subnetwork","type":"bytes32"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"setNetworkLimit","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"subnetwork","type":"bytes32"},{"internalType":"address","name":"operator","type":"address"},{"internalType":"uint256","name":"shares","type":"uint256"}],"name":"setOperatorNetworkShares","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"subnetwork","type":"bytes32"},{"internalType":"address","name":"operator","type":"address"}],"name":"stake","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"subnetwork","type":"bytes32"},{"internalType":"address","name":"operator","type":"address"},{"internalType":"uint48","name":"timestamp","type":"uint48"},{"internalType":"bytes","name":"hints","type":"bytes"}],"name":"stakeAt","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"target","type":"address"},{"internalType":"bytes","name":"data","type":"bytes"}],"name":"staticDelegateCall","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes4","name":"interfaceId","type":"bytes4"}],"name":"supportsInterface","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"subnetwork","type":"bytes32"}],"name":"totalOperatorNetworkShares","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"subnetwork","type":"bytes32"},{"internalType":"uint48","name":"timestamp","type":"uint48"},{"internalType":"bytes","name":"hint","type":"bytes"}],"name":"totalOperatorNetworkSharesAt","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"vault","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"}]',
        "full_restake_delegator": '[{"inputs":[{"internalType":"address","name":"networkRegistry","type":"address"},{"internalType":"address","name":"vaultFactory","type":"address"},{"internalType":"address","name":"operatorVaultOptInService","type":"address"},{"internalType":"address","name":"operatorNetworkOptInService","type":"address"},{"internalType":"address","name":"delegatorFactory","type":"address"},{"internalType":"uint64","name":"entityType","type":"uint64"}],"stateMutability":"nonpayable","type":"constructor"},{"inputs":[],"name":"AccessControlBadConfirmation","type":"error"},{"inputs":[{"internalType":"address","name":"account","type":"address"},{"internalType":"bytes32","name":"neededRole","type":"bytes32"}],"name":"AccessControlUnauthorizedAccount","type":"error"},{"inputs":[],"name":"AlreadySet","type":"error"},{"inputs":[],"name":"CheckpointUnorderedInsertion","type":"error"},{"inputs":[],"name":"DuplicateRoleHolder","type":"error"},{"inputs":[],"name":"ExceedsMaxNetworkLimit","type":"error"},{"inputs":[],"name":"InvalidInitialization","type":"error"},{"inputs":[],"name":"MissingRoleHolders","type":"error"},{"inputs":[],"name":"NotInitializing","type":"error"},{"inputs":[],"name":"NotNetwork","type":"error"},{"inputs":[],"name":"NotSlasher","type":"error"},{"inputs":[],"name":"NotVault","type":"error"},{"inputs":[{"internalType":"uint8","name":"bits","type":"uint8"},{"internalType":"uint256","name":"value","type":"uint256"}],"name":"SafeCastOverflowedUintDowncast","type":"error"},{"inputs":[],"name":"ZeroAddressRoleHolder","type":"error"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"uint64","name":"version","type":"uint64"}],"name":"Initialized","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"subnetwork","type":"bytes32"},{"indexed":true,"internalType":"address","name":"operator","type":"address"},{"indexed":false,"internalType":"uint256","name":"slashedAmount","type":"uint256"}],"name":"OnSlash","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"role","type":"bytes32"},{"indexed":true,"internalType":"bytes32","name":"previousAdminRole","type":"bytes32"},{"indexed":true,"internalType":"bytes32","name":"newAdminRole","type":"bytes32"}],"name":"RoleAdminChanged","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"role","type":"bytes32"},{"indexed":true,"internalType":"address","name":"account","type":"address"},{"indexed":true,"internalType":"address","name":"sender","type":"address"}],"name":"RoleGranted","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"role","type":"bytes32"},{"indexed":true,"internalType":"address","name":"account","type":"address"},{"indexed":true,"internalType":"address","name":"sender","type":"address"}],"name":"RoleRevoked","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"hook","type":"address"}],"name":"SetHook","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"subnetwork","type":"bytes32"},{"indexed":false,"internalType":"uint256","name":"amount","type":"uint256"}],"name":"SetMaxNetworkLimit","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"subnetwork","type":"bytes32"},{"indexed":false,"internalType":"uint256","name":"amount","type":"uint256"}],"name":"SetNetworkLimit","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"subnetwork","type":"bytes32"},{"indexed":true,"internalType":"address","name":"operator","type":"address"},{"indexed":false,"internalType":"uint256","name":"amount","type":"uint256"}],"name":"SetOperatorNetworkLimit","type":"event"},{"inputs":[],"name":"DEFAULT_ADMIN_ROLE","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"FACTORY","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"HOOK_SET_ROLE","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"NETWORK_LIMIT_SET_ROLE","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"NETWORK_REGISTRY","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"OPERATOR_NETWORK_LIMIT_SET_ROLE","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"OPERATOR_NETWORK_OPT_IN_SERVICE","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"OPERATOR_VAULT_OPT_IN_SERVICE","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"TYPE","outputs":[{"internalType":"uint64","name":"","type":"uint64"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"VAULT_FACTORY","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"VERSION","outputs":[{"internalType":"uint64","name":"","type":"uint64"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"role","type":"bytes32"}],"name":"getRoleAdmin","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"role","type":"bytes32"},{"internalType":"address","name":"account","type":"address"}],"name":"grantRole","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"role","type":"bytes32"},{"internalType":"address","name":"account","type":"address"}],"name":"hasRole","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"hook","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes","name":"data","type":"bytes"}],"name":"initialize","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"subnetwork","type":"bytes32"}],"name":"maxNetworkLimit","outputs":[{"internalType":"uint256","name":"value","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"subnetwork","type":"bytes32"}],"name":"networkLimit","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"subnetwork","type":"bytes32"},{"internalType":"uint48","name":"timestamp","type":"uint48"},{"internalType":"bytes","name":"hint","type":"bytes"}],"name":"networkLimitAt","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"subnetwork","type":"bytes32"},{"internalType":"address","name":"operator","type":"address"},{"internalType":"uint256","name":"slashedAmount","type":"uint256"},{"internalType":"uint48","name":"captureTimestamp","type":"uint48"},{"internalType":"bytes","name":"data","type":"bytes"}],"name":"onSlash","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"subnetwork","type":"bytes32"},{"internalType":"address","name":"operator","type":"address"}],"name":"operatorNetworkLimit","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"subnetwork","type":"bytes32"},{"internalType":"address","name":"operator","type":"address"},{"internalType":"uint48","name":"timestamp","type":"uint48"},{"internalType":"bytes","name":"hint","type":"bytes"}],"name":"operatorNetworkLimitAt","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"role","type":"bytes32"},{"internalType":"address","name":"callerConfirmation","type":"address"}],"name":"renounceRole","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"role","type":"bytes32"},{"internalType":"address","name":"account","type":"address"}],"name":"revokeRole","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"hook_","type":"address"}],"name":"setHook","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint96","name":"identifier","type":"uint96"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"setMaxNetworkLimit","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"subnetwork","type":"bytes32"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"setNetworkLimit","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"subnetwork","type":"bytes32"},{"internalType":"address","name":"operator","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"setOperatorNetworkLimit","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"subnetwork","type":"bytes32"},{"internalType":"address","name":"operator","type":"address"}],"name":"stake","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"subnetwork","type":"bytes32"},{"internalType":"address","name":"operator","type":"address"},{"internalType":"uint48","name":"timestamp","type":"uint48"},{"internalType":"bytes","name":"hints","type":"bytes"}],"name":"stakeAt","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"target","type":"address"},{"internalType":"bytes","name":"data","type":"bytes"}],"name":"staticDelegateCall","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes4","name":"interfaceId","type":"bytes4"}],"name":"supportsInterface","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"vault","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"}]',
        "veto_slasher": '[{"inputs":[{"internalType":"address","name":"vaultFactory","type":"address"},{"internalType":"address","name":"networkMiddlewareService","type":"address"},{"internalType":"address","name":"networkRegistry","type":"address"},{"internalType":"address","name":"slasherFactory","type":"address"},{"internalType":"uint64","name":"entityType","type":"uint64"}],"stateMutability":"nonpayable","type":"constructor"},{"inputs":[],"name":"CheckpointUnorderedInsertion","type":"error"},{"inputs":[],"name":"InsufficientSlash","type":"error"},{"inputs":[],"name":"InvalidCaptureTimestamp","type":"error"},{"inputs":[],"name":"InvalidInitialization","type":"error"},{"inputs":[],"name":"InvalidResolverSetEpochsDelay","type":"error"},{"inputs":[],"name":"InvalidVetoDuration","type":"error"},{"inputs":[],"name":"NotInitializing","type":"error"},{"inputs":[],"name":"NotNetwork","type":"error"},{"inputs":[],"name":"NotNetworkMiddleware","type":"error"},{"inputs":[],"name":"NotResolver","type":"error"},{"inputs":[],"name":"NotVault","type":"error"},{"inputs":[],"name":"OutdatedCaptureTimestamp","type":"error"},{"inputs":[{"internalType":"uint8","name":"bits","type":"uint8"},{"internalType":"uint256","name":"value","type":"uint256"}],"name":"SafeCastOverflowedUintDowncast","type":"error"},{"inputs":[],"name":"SlashPeriodEnded","type":"error"},{"inputs":[],"name":"SlashRequestCompleted","type":"error"},{"inputs":[],"name":"SlashRequestNotExist","type":"error"},{"inputs":[],"name":"VaultNotInitialized","type":"error"},{"inputs":[],"name":"VetoPeriodEnded","type":"error"},{"inputs":[],"name":"VetoPeriodNotEnded","type":"error"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"uint256","name":"slashIndex","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"slashedAmount","type":"uint256"}],"name":"ExecuteSlash","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"uint64","name":"version","type":"uint64"}],"name":"Initialized","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"uint256","name":"slashIndex","type":"uint256"},{"indexed":true,"internalType":"bytes32","name":"subnetwork","type":"bytes32"},{"indexed":true,"internalType":"address","name":"operator","type":"address"},{"indexed":false,"internalType":"uint256","name":"slashAmount","type":"uint256"},{"indexed":false,"internalType":"uint48","name":"captureTimestamp","type":"uint48"},{"indexed":false,"internalType":"uint48","name":"vetoDeadline","type":"uint48"}],"name":"RequestSlash","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"subnetwork","type":"bytes32"},{"indexed":false,"internalType":"address","name":"resolver","type":"address"}],"name":"SetResolver","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"uint256","name":"slashIndex","type":"uint256"},{"indexed":true,"internalType":"address","name":"resolver","type":"address"}],"name":"VetoSlash","type":"event"},{"inputs":[],"name":"FACTORY","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"NETWORK_MIDDLEWARE_SERVICE","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"NETWORK_REGISTRY","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"TYPE","outputs":[{"internalType":"uint64","name":"","type":"uint64"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"VAULT_FACTORY","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"subnetwork","type":"bytes32"},{"internalType":"address","name":"operator","type":"address"}],"name":"cumulativeSlash","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"subnetwork","type":"bytes32"},{"internalType":"address","name":"operator","type":"address"},{"internalType":"uint48","name":"timestamp","type":"uint48"},{"internalType":"bytes","name":"hint","type":"bytes"}],"name":"cumulativeSlashAt","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"slashIndex","type":"uint256"},{"internalType":"bytes","name":"hints","type":"bytes"}],"name":"executeSlash","outputs":[{"internalType":"uint256","name":"slashedAmount","type":"uint256"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes","name":"data","type":"bytes"}],"name":"initialize","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"subnetwork","type":"bytes32"}],"name":"latestSlashedCaptureTimestamp","outputs":[{"internalType":"uint48","name":"value","type":"uint48"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"subnetwork","type":"bytes32"},{"internalType":"address","name":"operator","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"},{"internalType":"uint48","name":"captureTimestamp","type":"uint48"},{"internalType":"bytes","name":"hints","type":"bytes"}],"name":"requestSlash","outputs":[{"internalType":"uint256","name":"slashIndex","type":"uint256"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"subnetwork","type":"bytes32"},{"internalType":"bytes","name":"hint","type":"bytes"}],"name":"resolver","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"subnetwork","type":"bytes32"},{"internalType":"uint48","name":"timestamp","type":"uint48"},{"internalType":"bytes","name":"hint","type":"bytes"}],"name":"resolverAt","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"resolverSetEpochsDelay","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint96","name":"identifier","type":"uint96"},{"internalType":"address","name":"resolver_","type":"address"},{"internalType":"bytes","name":"hints","type":"bytes"}],"name":"setResolver","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint256","name":"","type":"uint256"}],"name":"slashRequests","outputs":[{"internalType":"bytes32","name":"subnetwork","type":"bytes32"},{"internalType":"address","name":"operator","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"},{"internalType":"uint48","name":"captureTimestamp","type":"uint48"},{"internalType":"uint48","name":"vetoDeadline","type":"uint48"},{"internalType":"bool","name":"completed","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"slashRequestsLength","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"subnetwork","type":"bytes32"},{"internalType":"address","name":"operator","type":"address"},{"internalType":"uint48","name":"captureTimestamp","type":"uint48"},{"internalType":"bytes","name":"hints","type":"bytes"}],"name":"slashableStake","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"target","type":"address"},{"internalType":"bytes","name":"data","type":"bytes"}],"name":"staticDelegateCall","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"vault","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"vetoDuration","outputs":[{"internalType":"uint48","name":"","type":"uint48"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"slashIndex","type":"uint256"},{"internalType":"bytes","name":"hints","type":"bytes"}],"name":"vetoSlash","outputs":[],"stateMutability":"nonpayable","type":"function"}]',
        "vault": '[{"inputs":[{"internalType":"address","name":"delegatorFactory","type":"address"},{"internalType":"address","name":"slasherFactory","type":"address"},{"internalType":"address","name":"vaultFactory","type":"address"}],"stateMutability":"nonpayable","type":"constructor"},{"inputs":[],"name":"AccessControlBadConfirmation","type":"error"},{"inputs":[{"internalType":"address","name":"account","type":"address"},{"internalType":"bytes32","name":"neededRole","type":"bytes32"}],"name":"AccessControlUnauthorizedAccount","type":"error"},{"inputs":[{"internalType":"address","name":"target","type":"address"}],"name":"AddressEmptyCode","type":"error"},{"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"AddressInsufficientBalance","type":"error"},{"inputs":[],"name":"AlreadyClaimed","type":"error"},{"inputs":[],"name":"AlreadyInitialized","type":"error"},{"inputs":[],"name":"AlreadySet","type":"error"},{"inputs":[],"name":"CheckpointUnorderedInsertion","type":"error"},{"inputs":[],"name":"FailedInnerCall","type":"error"},{"inputs":[],"name":"InsufficientClaim","type":"error"},{"inputs":[],"name":"InsufficientDeposit","type":"error"},{"inputs":[],"name":"InsufficientWithdrawal","type":"error"},{"inputs":[],"name":"InvalidAccount","type":"error"},{"inputs":[],"name":"InvalidCaptureEpoch","type":"error"},{"inputs":[],"name":"InvalidClaimer","type":"error"},{"inputs":[],"name":"InvalidCollateral","type":"error"},{"inputs":[],"name":"InvalidEpoch","type":"error"},{"inputs":[],"name":"InvalidEpochDuration","type":"error"},{"inputs":[],"name":"InvalidInitialVersion","type":"error"},{"inputs":[],"name":"InvalidInitialization","type":"error"},{"inputs":[],"name":"InvalidLengthEpochs","type":"error"},{"inputs":[],"name":"InvalidOnBehalfOf","type":"error"},{"inputs":[],"name":"InvalidRecipient","type":"error"},{"inputs":[],"name":"InvalidTimestamp","type":"error"},{"inputs":[],"name":"MathOverflowedMulDiv","type":"error"},{"inputs":[],"name":"MissingRoles","type":"error"},{"inputs":[],"name":"NoDepositWhitelist","type":"error"},{"inputs":[],"name":"NoPreviousEpoch","type":"error"},{"inputs":[],"name":"NotDelegator","type":"error"},{"inputs":[],"name":"NotFactory","type":"error"},{"inputs":[],"name":"NotInitializing","type":"error"},{"inputs":[],"name":"NotSlasher","type":"error"},{"inputs":[],"name":"NotWhitelistedDepositor","type":"error"},{"inputs":[{"internalType":"address","name":"owner","type":"address"}],"name":"OwnableInvalidOwner","type":"error"},{"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"OwnableUnauthorizedAccount","type":"error"},{"inputs":[],"name":"ReentrancyGuardReentrantCall","type":"error"},{"inputs":[{"internalType":"uint8","name":"bits","type":"uint8"},{"internalType":"uint256","name":"value","type":"uint256"}],"name":"SafeCastOverflowedUintDowncast","type":"error"},{"inputs":[{"internalType":"address","name":"token","type":"address"}],"name":"SafeERC20FailedOperation","type":"error"},{"inputs":[],"name":"TooMuchWithdraw","type":"error"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"claimer","type":"address"},{"indexed":true,"internalType":"address","name":"recipient","type":"address"},{"indexed":false,"internalType":"uint256","name":"epoch","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"amount","type":"uint256"}],"name":"Claim","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"claimer","type":"address"},{"indexed":true,"internalType":"address","name":"recipient","type":"address"},{"indexed":false,"internalType":"uint256[]","name":"epochs","type":"uint256[]"},{"indexed":false,"internalType":"uint256","name":"amount","type":"uint256"}],"name":"ClaimBatch","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"depositor","type":"address"},{"indexed":true,"internalType":"address","name":"onBehalfOf","type":"address"},{"indexed":false,"internalType":"uint256","name":"amount","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"shares","type":"uint256"}],"name":"Deposit","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"uint64","name":"version","type":"uint64"}],"name":"Initialized","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"slasher","type":"address"},{"indexed":false,"internalType":"uint256","name":"slashedAmount","type":"uint256"}],"name":"OnSlash","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"previousOwner","type":"address"},{"indexed":true,"internalType":"address","name":"newOwner","type":"address"}],"name":"OwnershipTransferred","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"role","type":"bytes32"},{"indexed":true,"internalType":"bytes32","name":"previousAdminRole","type":"bytes32"},{"indexed":true,"internalType":"bytes32","name":"newAdminRole","type":"bytes32"}],"name":"RoleAdminChanged","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"role","type":"bytes32"},{"indexed":true,"internalType":"address","name":"account","type":"address"},{"indexed":true,"internalType":"address","name":"sender","type":"address"}],"name":"RoleGranted","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"bytes32","name":"role","type":"bytes32"},{"indexed":true,"internalType":"address","name":"account","type":"address"},{"indexed":true,"internalType":"address","name":"sender","type":"address"}],"name":"RoleRevoked","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"bool","name":"depositWhitelist","type":"bool"}],"name":"SetDepositWhitelist","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"account","type":"address"},{"indexed":false,"internalType":"bool","name":"status","type":"bool"}],"name":"SetDepositorWhitelistStatus","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"withdrawer","type":"address"},{"indexed":true,"internalType":"address","name":"claimer","type":"address"},{"indexed":false,"internalType":"uint256","name":"amount","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"burnedShares","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"mintedShares","type":"uint256"}],"name":"Withdraw","type":"event"},{"inputs":[],"name":"DEFAULT_ADMIN_ROLE","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"DELEGATOR_FACTORY","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"DEPOSITOR_WHITELIST_ROLE","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"DEPOSIT_WHITELIST_SET_ROLE","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"FACTORY","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"SLASHER_FACTORY","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"activeBalanceOf","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"account","type":"address"},{"internalType":"uint48","name":"timestamp","type":"uint48"},{"internalType":"bytes","name":"hints","type":"bytes"}],"name":"activeBalanceOfAt","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"activeShares","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint48","name":"timestamp","type":"uint48"},{"internalType":"bytes","name":"hint","type":"bytes"}],"name":"activeSharesAt","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"activeSharesOf","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"account","type":"address"},{"internalType":"uint48","name":"timestamp","type":"uint48"},{"internalType":"bytes","name":"hint","type":"bytes"}],"name":"activeSharesOfAt","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"activeStake","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint48","name":"timestamp","type":"uint48"},{"internalType":"bytes","name":"hint","type":"bytes"}],"name":"activeStakeAt","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"balanceOf","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"burner","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"recipient","type":"address"},{"internalType":"uint256","name":"epoch","type":"uint256"}],"name":"claim","outputs":[{"internalType":"uint256","name":"amount","type":"uint256"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"recipient","type":"address"},{"internalType":"uint256[]","name":"epochs","type":"uint256[]"}],"name":"claimBatch","outputs":[{"internalType":"uint256","name":"amount","type":"uint256"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"collateral","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"currentEpoch","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"currentEpochStart","outputs":[{"internalType":"uint48","name":"","type":"uint48"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"delegator","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"onBehalfOf","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"deposit","outputs":[{"internalType":"uint256","name":"depositedAmount","type":"uint256"},{"internalType":"uint256","name":"mintedShares","type":"uint256"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"depositWhitelist","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint48","name":"timestamp","type":"uint48"}],"name":"epochAt","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"epochDuration","outputs":[{"internalType":"uint48","name":"","type":"uint48"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"epochDurationInit","outputs":[{"internalType":"uint48","name":"","type":"uint48"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"role","type":"bytes32"}],"name":"getRoleAdmin","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"role","type":"bytes32"},{"internalType":"address","name":"account","type":"address"}],"name":"grantRole","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"role","type":"bytes32"},{"internalType":"address","name":"account","type":"address"}],"name":"hasRole","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint64","name":"initialVersion","type":"uint64"},{"internalType":"address","name":"owner_","type":"address"},{"internalType":"bytes","name":"data","type":"bytes"}],"name":"initialize","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"isDepositorWhitelisted","outputs":[{"internalType":"bool","name":"value","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"epoch","type":"uint256"},{"internalType":"address","name":"account","type":"address"}],"name":"isWithdrawalsClaimed","outputs":[{"internalType":"bool","name":"value","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint64","name":"newVersion","type":"uint64"},{"internalType":"bytes","name":"data","type":"bytes"}],"name":"migrate","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"nextEpochStart","outputs":[{"internalType":"uint48","name":"","type":"uint48"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"slashedAmount","type":"uint256"},{"internalType":"uint48","name":"captureTimestamp","type":"uint48"}],"name":"onSlash","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"owner","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"previousEpochStart","outputs":[{"internalType":"uint48","name":"","type":"uint48"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"renounceOwnership","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"role","type":"bytes32"},{"internalType":"address","name":"callerConfirmation","type":"address"}],"name":"renounceRole","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"role","type":"bytes32"},{"internalType":"address","name":"account","type":"address"}],"name":"revokeRole","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bool","name":"status","type":"bool"}],"name":"setDepositWhitelist","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"account","type":"address"},{"internalType":"bool","name":"status","type":"bool"}],"name":"setDepositorWhitelistStatus","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"slasher","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"target","type":"address"},{"internalType":"bytes","name":"data","type":"bytes"}],"name":"staticDelegateCall","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes4","name":"interfaceId","type":"bytes4"}],"name":"supportsInterface","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"totalStake","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"newOwner","type":"address"}],"name":"transferOwnership","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"version","outputs":[{"internalType":"uint64","name":"","type":"uint64"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"claimer","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"withdraw","outputs":[{"internalType":"uint256","name":"burnedShares","type":"uint256"},{"internalType":"uint256","name":"mintedShares","type":"uint256"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint256","name":"epoch","type":"uint256"}],"name":"withdrawalShares","outputs":[{"internalType":"uint256","name":"amount","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"epoch","type":"uint256"},{"internalType":"address","name":"account","type":"address"}],"name":"withdrawalSharesOf","outputs":[{"internalType":"uint256","name":"amount","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"epoch","type":"uint256"}],"name":"withdrawals","outputs":[{"internalType":"uint256","name":"amount","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"epoch","type":"uint256"},{"internalType":"address","name":"account","type":"address"}],"name":"withdrawalsOf","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"}]',
        "erc20": '[{"constant":true,"inputs":[],"name":"name","outputs":[{"name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_spender","type":"address"},{"name":"_value","type":"uint256"}],"name":"approve","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"totalSupply","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_from","type":"address"},{"name":"_to","type":"address"},{"name":"_value","type":"uint256"}],"name":"transferFrom","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"decimals","outputs":[{"name":"","type":"uint8"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"name":"_owner","type":"address"}],"name":"balanceOf","outputs":[{"name":"balance","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"symbol","outputs":[{"name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_to","type":"address"},{"name":"_value","type":"uint256"}],"name":"transfer","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"name":"_owner","type":"address"},{"name":"_spender","type":"address"}],"name":"allowance","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"payable":true,"stateMutability":"payable","type":"fallback"},{"anonymous":false,"inputs":[{"indexed":true,"name":"owner","type":"address"},{"indexed":true,"name":"spender","type":"address"},{"indexed":false,"name":"value","type":"uint256"}],"name":"Approval","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"name":"from","type":"address"},{"indexed":true,"name":"to","type":"address"},{"indexed":false,"name":"value","type":"uint256"}],"name":"Transfer","type":"event"}]',
    }

    ADDRESSES = {
        "op_registry": "0xa02C55a6306c859517A064fb34d48DFB773A4a52",
        "net_registry": "0x5dEA088d2Be1473d948895cc26104bcf103CEf3E",
        "op_vault_opt_in": "0x63E459f3E2d8F7f5E4AdBA55DE6c50CbB43dD563",
        "op_net_opt_in": "0x973ba45986FF71742129d23C4138bb3fAd4f13A5",
        "middleware_service": "0x70818a53ddE5c2e78Edfb6f6b277Be9a71fa894E",
        "vault_factory": "0x5035c15F3cb4364CF2cF35ca53E3d6FC45FC8899",
    }

    DELEGATOR_TYPES_ENTITIES = {
        0: "network_restake_delegator",
        1: "full_restake_delegator",
    }

    DELEGATOR_TYPES_NAMES = {
        0: "NetworkRestake",
        1: "FullRestake",
    }

    SLASHER_TYPES_NAMES = {
        -1: "NonSlashable",
        0: "InstantSlasher",
        1: "VetoSlasher",
    }

    def __init__(self, provider):
        self.provider = provider
        self.w3 = Web3(Web3.HTTPProvider(provider))
        self.contracts = {}
        self._cache = {"token_meta": {}}
        self.init_contracts()

    def init_contracts(self):
        for name, address in self.ADDRESSES.items():
            self.contracts[name] = self.w3.eth.contract(
                address=address, abi=self.ABIS[name]
            )

    def normalize_address(self, address):
        return Web3.to_checksum_address(address)

    def get_token_meta(self, token):
        token = self.normalize_address(token)

        if token in self._cache["token_meta"]:
            return self._cache["token_meta"][token]
        w3_multicall = W3Multicall(self.w3)
        w3_multicall.add(W3Multicall.Call(token, "symbol()(string)"))
        w3_multicall.add(W3Multicall.Call(token, "decimals()(uint8)"))
        res = w3_multicall.call()
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
                    self.ADDRESSES["net_registry"], "entity(uint256)(address)", i
                )
            )
        nets = w3_multicall.call()
        nets = [self.normalize_address(net) for net in nets]
        w3_multicall = W3Multicall(self.w3)
        for net in nets:
            w3_multicall.add(
                W3Multicall.Call(
                    self.ADDRESSES["middleware_service"],
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
                    self.ADDRESSES["op_registry"], "entity(uint256)(address)", i
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
                    self.ADDRESSES["op_net_opt_in"],
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
                    self.ADDRESSES["op_net_opt_in"],
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
                    self.ADDRESSES["vault_factory"], "entity(uint256)(address)", i
                )
            )
        vaults = w3_multicall.call()
        vaults = [self.normalize_address(vault) for vault in vaults]
        w3_multicall = W3Multicall(self.w3)
        for vault in vaults:
            w3_multicall.add(W3Multicall.Call(vault, "collateral()(address)"))
            w3_multicall.add(W3Multicall.Call(vault, "delegator()(address)"))
            w3_multicall.add(W3Multicall.Call(vault, "slasher()(address)"))
        collaterals = w3_multicall.call()
        results = []
        for i, vault in enumerate(vaults):
            results.append(
                {
                    "vault": vault,
                    "collateral": self.normalize_address(collaterals[3 * i]),
                    "delegator": self.normalize_address(collaterals[3 * i + 1]),
                    "slasher": self.normalize_address(collaterals[3 * i + 2]),
                    "delegator_type": -1,
                    "slasher_type": -1,
                }
            )
        # Get types
        w3_multicall = W3Multicall(self.w3)
        rev_result_idxs = []
        for idx, vault_info in enumerate(results):
            w3_multicall.add(
                W3Multicall.Call(vault_info["delegator"], "TYPE()(uint64)")
            )
            rev_result_idxs.append((idx, "delegator"))
            if vault_info["slasher"] != "0x0000000000000000000000000000000000000000":
                w3_multicall.add(
                    W3Multicall.Call(vault_info["slasher"], "TYPE()(uint64)")
                )
                rev_result_idxs.append((idx, "slasher"))
        types = w3_multicall.call()
        for (idx, role), type_value in zip(rev_result_idxs, types):
            if role == "delegator":
                results[idx]["delegator_type"] = type_value
            elif role == "slasher":
                results[idx]["slasher_type"] = type_value
        return results

    def get_net_vaults(self, net):
        """Fetch all vaults in a given network."""
        net = self.normalize_address(net)
        vaults = self.get_vaults()
        w3_multicall = W3Multicall(self.w3)
        for vault in vaults:
            w3_multicall.add(
                W3Multicall.Call(
                    vault["delegator"],
                    "networkLimit(bytes32)(uint256)",
                    bytes.fromhex(net[2:]),  # TODO: fix subnets
                )
            )

        limits = w3_multicall.call()
        results = []
        for i, limit in enumerate(limits):
            if limit and limit > 0:
                vaults[i]["limit"] = limit
                results.append(vaults[i])

        return results

    def get_net_ops_vaults(self, net):
        """Fetch the stakes of all operators in a given network."""
        net = self.normalize_address(net)
        vaults = self.get_net_vaults(net)
        ops = self.get_net_ops(net)

        w3_multicall = W3Multicall(self.w3)
        for op in ops:
            for vault in vaults:
                w3_multicall.add(
                    W3Multicall.Call(
                        vault["delegator"],
                        "stake(bytes32,address)(uint256)",
                        [bytes.fromhex(net[2:]), op],  # TODO: fix subnets
                    )
                )

        stakes = w3_multicall.call()
        results = [{"op": op, "vaults": []} for op in ops]
        i = 0
        for op_idx in range(len(ops)):
            for vault in vaults:
                if stakes[i] > 0:
                    vault["stake"] = stakes[i]
                    results[op_idx]["vaults"].append(vault)
                i += 1

        return results

    def get_op_nets_vaults(self, op):
        """Fetch stakes of an operator in all networks."""
        op = self.normalize_address(op)
        nets = self.get_op_nets(op)  # Fetch networks where the operator is opted in

        w3_multicall = W3Multicall(self.w3)
        net_vaults = {}
        for net in nets:
            # Get vaults in each network
            net_vaults[net["net"]] = self.get_net_vaults(net["net"])
            for vault in net_vaults[net["net"]]:
                # Add multicalls to fetch stakes of the operator in each vault
                w3_multicall.add(
                    W3Multicall.Call(
                        vault["delegator"],
                        "stake(bytes32,address)(uint256)",
                        [bytes.fromhex(net["net"][2:]), op],  # TODO: fix subnets
                    )
                )

        stakes = w3_multicall.call()
        results = [{"net": net["net"], "vaults": []} for net in nets]
        i = 0
        for net_idx in range(len(nets)):
            for vault in net_vaults[nets[net_idx]["net"]]:
                if stakes[i] > 0:
                    vault["stake"] = stakes[i]
                    results[net_idx]["vaults"].append(vault)
                i += 1

        return results

    def get_vault_ops(self, vault):
        """Get all operators that are opted into a given vault."""
        vault = self.normalize_address(vault)
        ops = self.get_ops()
        w3_multicall = W3Multicall(self.w3)

        for op in ops:
            w3_multicall.add(
                W3Multicall.Call(
                    self.ADDRESSES["op_vault_opt_in"],
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
            w3_multicall.add(
                W3Multicall.Call(
                    delegator,
                    "maxNetworkLimit(bytes32)(uint256)",
                    bytes.fromhex(net["net"][2:]),  # TODO: fix subnets
                )
            )

        net_associations = w3_multicall.call()

        return [
            {
                "net": net["net"],
                "limit": associated,
            }
            for net, associated in zip(nets, net_associations)
            if associated > 0
        ]

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
                        self.ADDRESSES["op_net_opt_in"],
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
            {"from": who, "nonce": self.w3.eth.get_transaction_count(who), **kwargs}
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
            print(f"Failed! Reason: {e}")

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
    "--provider",
    default="https://ethereum-holesky-rpc.publicnode.com",
    help="Ethereum provider URL [http(s)]",
)
@click.pass_context
def cli(ctx, provider):
    ctx.obj = SymbioticCLI(provider)


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
@click.pass_context
def nets(ctx):
    """List all networks."""
    nets = ctx.obj.get_nets()
    print(f"All networks [{len(nets)} total]:")
    for net in nets:
        ctx.obj.print_indented(f'Network: {net["net"]}', indent=2)
        ctx.obj.print_indented(f'Middleware: {net["middleware"]}\n', indent=4)


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
                ctx.obj.print_indented(
                    f'Stake: {vault["stake"] / 10 ** token_meta["decimals"]}', indent=8
                )
                stakes_sum += vault["stake"]
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

    subnetwork = network_address + (64 - 40) * "0"  # TODO: fix subnets

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
        percent = operator_network_shares / total_operator_network_shares * 100

        print(
            f"Operator stake\nin vault = {vault_address}\nfor subnetwork = {subnetwork}\nis {stake_normalized} {collateral_symbol}\nwhich is {percent}% ({operator_network_shares} / {total_operator_network_shares} in shares) of network stake"
        )
    else:
        print(
            f"Operator stake in vault = {vault_address}\nfor subnetwork = {subnetwork}\nis {stake}"
        )


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
                ctx.obj.print_indented(
                    f'Stake: {vault["stake"] / 10 ** token_meta["decimals"]}', indent=8
                )
                stakes_sum += vault["stake"]
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
@click.pass_context
def vaults(ctx):
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
            f'Slasher: {vault["slasher"]} ({slasher_type})\n', indent=4
        )


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
    ADDRESS - an address to get an active balance for
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
    EPOCH - an epoch to get withdrawals for
    ADDRESS - an address to get an active balance for
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

    ctx.obj.process_write_transaction(
        private_key,
        ledger,
        ledger_address,
        "net_registry",
        ctx.obj.ADDRESSES["net_registry"],
        "registerNetwork",
        success_message=f"Successfully registered as a network",
    )


@cli.command()
@click.argument("vault_address", type=address_type)
@click.argument("max_limit", type=uint256_type)
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
    ctx, vault_address, max_limit, private_key, ledger, ledger_address
):
    """Set a maximum network limit at the vault's delegator.

    \b
    VAULT_ADDRESS - an address of the vault to set a maximum limit for
    MAX_LIMIT - a maximum amount of stake a network is ready to get from the vault (in wei)
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
        0,  # TODO: fix subnets
        max_limit,
        success_message=f"Successfully set max limit = {max_limit} in vault = {vault_address}",
    )


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

    subnetwork = network_address + (64 - 40) * "0"  # TODO: fix subnets

    slasher = ctx.obj.get_slasher(vault_address)
    slasher_type = ctx.obj.get_entity_type(slasher)

    if slasher_type != 1:
        print("It is not a VetoSlasher.")
        return

    resolver = ctx.obj.get_resolver(slasher, subnetwork)
    print(
        f"Resolver for subnetwork = {subnetwork} at vault {vault_address} is {resolver}"
    )


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

    subnetwork = network_address + (64 - 40) * "0"  # TODO: fix subnets

    slasher = ctx.obj.get_slasher(vault_address)
    slasher_type = ctx.obj.get_entity_type(slasher)

    if slasher_type != 1:
        print("It is not a VetoSlasher.")
        return

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


@cli.command()
@click.argument("vault_address", type=address_type)
@click.argument("resolver", type=address_type)
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
def set_resolver(ctx, vault_address, resolver, private_key, ledger, ledger_address):
    """Set a resolver for a subnetwork at VetoSlasher.

    \b
    VAULT_ADDRESS - an address of the vault to set a resolver for
    RESOLVER - an address of the resolver to set
    """
    vault_address = ctx.obj.normalize_address(vault_address)
    resolver = ctx.obj.normalize_address(resolver)

    slasher = ctx.obj.get_slasher(vault_address)
    slasher_type = ctx.obj.get_entity_type(slasher)

    if slasher_type != 1:
        print("It is not a VetoSlasher.")
        return

    net = ctx.obj.get_address(private_key, ledger, ledger_address)

    identifier = 0
    subnetwork = net + (64 - 40) * "0"  # TODO: fix subnets

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
        identifier,
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

    ctx.obj.process_write_transaction(
        private_key,
        ledger,
        ledger_address,
        "op_registry",
        ctx.obj.ADDRESSES["op_registry"],
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
        ctx.obj.ADDRESSES["op_vault_opt_in"],
        "optIn",
        vault_address,
        success_message=f"Successfully opted in to vault = {vault_address}",
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
        ctx.obj.ADDRESSES["op_vault_opt_in"],
        "optOut",
        vault_address,
        success_message=f"Successfully opted out from vault = {vault_address}",
    )


@cli.command()
@click.argument("operator_address", type=address_type)
@click.argument("vault_address", type=address_type)
@click.pass_context
def check_opt_in_vault(ctx, operator_address, vault_address):
    """Check if is opted in to a vault.

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
        ctx.obj.ADDRESSES["op_net_opt_in"],
        "optIn",
        network_address,
        success_message=f"Successfully opted in to network = {network_address}",
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
        ctx.obj.ADDRESSES["op_net_opt_in"],
        "optOut",
        network_address,
        success_message=f"Successfully opted out from network = {network_address}",
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


### VAULT CURATOR CLI COMMANDS ###


@cli.command()
@click.argument("vault_address", type=address_type)
@click.argument("network_address", type=address_type)
@click.argument("limit", type=uint256_type)
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
    ctx, vault_address, network_address, limit, private_key, ledger, ledger_address
):
    """Set a network limit at the vault's delegator.

    \b
    VAULT_ADDRESS - an address of the vault to adjust the delegations for
    NETWORK_ADDRESS - an address of the network to set a limit for
    LIMIT - a maximum amount of stake the network can get (in wei)
    """
    vault_address = ctx.obj.normalize_address(vault_address)
    network_address = ctx.obj.normalize_address(network_address)

    subnetwork = network_address + (64 - 40) * "0"  # TODO: fix subnets

    delegator = ctx.obj.get_delegator(vault_address)
    delegator_type = ctx.obj.get_entity_type(delegator)

    if delegator_type not in [0, 1]:
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
@click.argument("operator_address", type=address_type)
@click.argument("limit", type=uint256_type)
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
    """
    vault_address = ctx.obj.normalize_address(vault_address)
    network_address = ctx.obj.normalize_address(network_address)
    operator_address = ctx.obj.normalize_address(operator_address)

    subnetwork = network_address + (64 - 40) * "0"  # TODO: fix subnets

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
@click.argument("shares", type=uint256_type)
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
    """
    vault_address = ctx.obj.normalize_address(vault_address)
    network_address = ctx.obj.normalize_address(network_address)
    operator_address = ctx.obj.normalize_address(operator_address)

    subnetwork = network_address + (64 - 40) * "0"  # TODO: fix subnets

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
    percentage = shares / new_total_operator_network_shares * 100

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
    VAULT_ADDRESS - an address of the vault to adjust the delegations for
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
    VAULT_ADDRESS - an address of the vault to adjust the delegations for
    AMOUNT - an amount of tokens to deposit (in the token value, e.g., 1000 for 1000 ETH)
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
    VAULT_ADDRESS - an address of the vault to adjust the delegations for
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
