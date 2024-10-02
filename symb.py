import click
from web3 import Web3
from w3multicall.multicall import W3Multicall
import ledgereth
from eth_account import Account


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
        if token in self._cache["token_meta"]:
            return self._cache["token_meta"][token]
        w3_multicall = W3Multicall(self.w3)
        w3_multicall.add(
            W3Multicall.Call(self.normalize_address(token), "symbol()(string)")
        )
        w3_multicall.add(
            W3Multicall.Call(self.normalize_address(token), "decimals()(uint8)")
        )
        res = w3_multicall.call()
        if not res[0] or not res[1]:
            meta = {"symbol": "Unknown", "decimals": 0}
        else:
            meta = {"symbol": res[0], "decimals": int(res[1])}
        self._cache["token_meta"][token] = meta
        return meta

    def get_middleware(self, net):
        return (
            self.contracts["middleware_service"]
            .functions.middleware(self.normalize_address(net))
            .call()
        )

    def get_delegator(self, vault):
        w3_multicall = W3Multicall(self.w3)
        w3_multicall.add(W3Multicall.Call(vault, "delegator()(address)"))
        return w3_multicall.call()[0]

    def get_slasher(self, vault):
        w3_multicall = W3Multicall(self.w3)
        w3_multicall.add(W3Multicall.Call(vault, "slasher()(address)"))
        return w3_multicall.call()[0]

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
        return w3_multicall.call()

    def get_op_nets(self, operator):
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
                    "collateral": collaterals[3 * i],
                    "delegator": collaterals[3 * i + 1],
                    "slasher": collaterals[3 * i + 2],
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

    def print_indented(self, *args, indent=2):
        print(" " * indent + " ".join(map(str, args)))

    def get_data(self, entity, address, function_name, *args, **kwargs):
        contract = self.w3.eth.contract(address=address, abi=self.ABIS[entity])

        return contract.functions[function_name](*args).call(kwargs)

    def get_transaction(self, who, entity, address, function_name, *args, **kwargs):
        contract = self.w3.eth.contract(address=address, abi=self.ABIS[entity])

        return contract.functions[function_name](*args).build_transaction(
            {"from": who, "nonce": self.w3.eth.get_transaction_count(who), **kwargs}
        )

    def get_transaction_ledger(
        self, ledger_account, entity, address, function_name, *args, **kwargs
    ):
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

            else:
                who = Account.from_key(private_key).address

                tx = self.get_transaction(who, entity, to, function_name, *args)

                tx_receipt = self.send_transaction(tx, private_key)

            print(success_message)

            return tx_receipt

        except Exception as e:
            print(f"Failed! Reason: {e}")


# CLI Commands
@click.group()
@click.option(
    "--provider",
    default="https://ethereum-holesky-rpc.publicnode.com",
    help="Ethereum provider URL [http(s)]",
)
@click.pass_context
def cli(ctx, provider):
    ctx.obj = SymbioticCLI(provider)


@cli.command()
@click.argument("address")
@click.pass_context
def isop(ctx, address):
    """Check if address is operator"""
    address = ctx.obj.normalize_address(address)
    is_op = ctx.obj.contracts["op_registry"].functions.isEntity(address).call()
    print(is_op)


@cli.command()
@click.argument("address")
@click.pass_context
def isnet(ctx, address):
    """Check if address is network"""
    address = ctx.obj.normalize_address(address)
    is_net = ctx.obj.contracts["net_registry"].functions.isEntity(address).call()
    print(is_net)


@cli.command()
@click.argument("address")
@click.pass_context
def middleware(ctx, address):
    """Get network middleware address"""
    address = ctx.obj.normalize_address(address)
    middleware_address = ctx.obj.get_middleware(address)
    print(middleware_address)


@cli.command()
@click.pass_context
def nets(ctx):
    """List all networks"""
    nets = ctx.obj.get_nets()
    print(f"All networks [{len(nets)} total]:")
    for net in nets:
        print(f'  Network: {net["net"]}')
        print(f'    Middleware: {net["middleware"]}\n')


@cli.command()
@click.pass_context
def ops(ctx):
    """List all operators"""
    ops = ctx.obj.get_ops()
    print(f"All operators [{len(ops)} total]:")
    for op in ops:
        print(f"  Operator: {op}")


@cli.command()
@click.pass_context
def vaults(ctx):
    """List all vaults"""
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
@click.argument("address")
@click.pass_context
def opnets(ctx, address):
    """List all networks where operator is opted in"""
    address = ctx.obj.normalize_address(address)
    print(f"Operator: {address}")
    nets = ctx.obj.get_op_nets(address)
    print(f"Networks [{len(nets)} total]:")
    for net in nets:
        print(f'  Network: {net["net"]}')


@cli.command()
@click.argument("address")
@click.pass_context
def netops(ctx, address):
    """List all operators opted in network"""
    address = ctx.obj.normalize_address(address)
    print(f"Network: {address}")
    ops = ctx.obj.get_net_ops(address)
    print(f"Operators [{len(ops)} total]:")
    for op in ops:
        ctx.obj.print_indented(f"Operator: {op}")


@cli.command()
@click.argument("address")
@click.pass_context
def netstakes(ctx, address):
    """Show stakes of all operators in network"""
    address = ctx.obj.normalize_address(address)
    print(f"Network: {address}")
    print(f"Middleware: {ctx.obj.get_middleware(address)}")

    opsvaults = ctx.obj.get_net_ops_vaults(address)
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


@cli.command()
@click.argument("address")
@click.pass_context
def opstakes(ctx, address):
    """Show operator stakes in all networks"""
    address = ctx.obj.normalize_address(address)
    print(f"Operator: {address}")

    netsvaults = ctx.obj.get_op_nets_vaults(address)
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


@cli.command()
@click.argument("vault_address")
@click.pass_context
def vaultops(ctx, vault_address):
    """List all operators opted into the given vault."""
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
@click.argument("vault_address")
@click.pass_context
def vaultnets(ctx, vault_address):
    """List all networks associated with the given vault."""
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
@click.argument("vault_address")
@click.pass_context
def vaultnetsops(ctx, vault_address):
    """List all operators and their associated networks for the given vault."""
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


@cli.command()
@click.option("--private-key", type=str)
@click.option("--ledger", is_flag=True)
@click.option(
    "--ledger-address",
    type=str,
    help="Address of the account to use for signing (the first one if not provided)",
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
@click.option("--private-key", type=str)
@click.option("--ledger", is_flag=True)
@click.option(
    "--ledger-address",
    type=str,
    help="Address of the account to use for signing (the first one if not provided)",
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
@click.argument("vault_address", type=str)
@click.argument("max_limit", type=int)
@click.option("--private-key", type=str)
@click.option("--ledger", is_flag=True)
@click.option(
    "--ledger-address",
    type=str,
    help="Address of the account to use for signing (the first one if not provided)",
)
@click.pass_context
def set_max_network_limit(
    ctx, vault_address, max_limit, private_key, ledger, ledger_address
):
    """Set a maximum network limit at the vault's delegator."""
    vault_address = ctx.obj.normalize_address(vault_address)

    delegator = ctx.obj.get_delegator(vault_address)
    delegator = ctx.obj.normalize_address(delegator)

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
@click.argument("vault_address", type=str)
@click.argument("network_address", type=str)
@click.argument("limit", type=int)
@click.option("--private-key", type=str)
@click.option("--ledger", is_flag=True)
@click.option(
    "--ledger-address",
    type=str,
    help="Address of the account to use for signing (the first one if not provided)",
)
@click.pass_context
def set_network_limit(
    ctx, vault_address, network_address, limit, private_key, ledger, ledger_address
):
    """Set a network limit at the vault's delegator."""
    vault_address = ctx.obj.normalize_address(vault_address)
    network_address = ctx.obj.normalize_address(network_address)

    delegator = ctx.obj.get_delegator(vault_address)
    delegator = ctx.obj.normalize_address(delegator)
    delegator_type = ctx.obj.get_data("entity", delegator, "TYPE")

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
        network_address + (64 - 40) * "0",
        limit,
        success_message=f"Successfully set limit = {limit} for network = {network_address}",
    )


@cli.command()
@click.argument("vault_address", type=str)
@click.argument("network_address", type=str)
@click.argument("operator_address", type=str)
@click.argument("limit", type=int)
@click.option("--private-key", type=str)
@click.option("--ledger", is_flag=True)
@click.option(
    "--ledger-address",
    type=str,
    help="Address of the account to use for signing (the first one if not provided)",
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
    """Set a operator-network limit at the vault's delegator."""
    vault_address = ctx.obj.normalize_address(vault_address)
    network_address = ctx.obj.normalize_address(network_address)
    operator_address = ctx.obj.normalize_address(operator_address)

    delegator = ctx.obj.get_delegator(vault_address)
    delegator = ctx.obj.normalize_address(delegator)
    delegator_type = ctx.obj.get_data("entity", delegator, "TYPE")

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
        network_address + (64 - 40) * "0",
        operator_address,
        limit,
        success_message=f"Successfully set limit = {limit} for operator = {operator_address} in network = {network_address}",
    )


@cli.command()
@click.argument("vault_address", type=str)
@click.argument("network_address", type=str)
@click.argument("operator_address", type=str)
@click.argument("shares", type=int)
@click.option("--private-key", type=str)
@click.option("--ledger", is_flag=True)
@click.option(
    "--ledger-address",
    type=str,
    help="Address of the account to use for signing (the first one if not provided)",
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
    """Set a operator-network shares at the vault's delegator."""
    vault_address = ctx.obj.normalize_address(vault_address)
    network_address = ctx.obj.normalize_address(network_address)
    operator_address = ctx.obj.normalize_address(operator_address)

    delegator = ctx.obj.get_delegator(vault_address)
    delegator = ctx.obj.normalize_address(delegator)
    delegator_type = ctx.obj.get_data("entity", delegator, "TYPE")

    if delegator_type != 0:
        print("It is not a NetworkRestakeDelegator.")
        return

    ctx.obj.process_write_transaction(
        private_key,
        ledger,
        ledger_address,
        ctx.obj.DELEGATOR_TYPES_ENTITIES[delegator_type],
        delegator,
        "setOperatorNetworkShares",
        network_address + (64 - 40) * "0",
        operator_address,
        shares,
        success_message=f"Successfully set shares = {shares} for operator = {operator_address} in network = {network_address}",
    )


if __name__ == "__main__":
    cli()
