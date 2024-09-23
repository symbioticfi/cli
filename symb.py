import click
from web3 import Web3
from w3multicall.multicall import W3Multicall


class SymbioticCLI:
    ABIS = {
        "op_registry": '[{"inputs":[],"name":"EntityNotExist","type":"error"},{"inputs":[],"name":"OperatorAlreadyRegistered","type":"error"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"entity","type":"address"}],"name":"AddEntity","type":"event"},{"inputs":[{"internalType":"uint256","name":"index","type":"uint256"}],"name":"entity","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"entity_","type":"address"}],"name":"isEntity","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"registerOperator","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"totalEntities","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"}]',
        "net_registry": '[{"inputs":[],"name":"EntityNotExist","type":"error"},{"inputs":[],"name":"OperatorAlreadyRegistered","type":"error"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"entity","type":"address"}],"name":"AddEntity","type":"event"},{"inputs":[{"internalType":"uint256","name":"index","type":"uint256"}],"name":"entity","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"entity_","type":"address"}],"name":"isEntity","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"registerOperator","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"totalEntities","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"}]',
        "op_vault_opt_in": '[{"inputs":[{"internalType":"address","name":"whoRegistry","type":"address"},{"internalType":"address","name":"whereRegistry","type":"address"}],"stateMutability":"nonpayable","type":"constructor"},{"inputs":[],"name":"AlreadyOptedIn","type":"error"},{"inputs":[],"name":"CheckpointUnorderedInsertion","type":"error"},{"inputs":[],"name":"NotOptedIn","type":"error"},{"inputs":[],"name":"NotWhereEntity","type":"error"},{"inputs":[],"name":"NotWho","type":"error"},{"inputs":[],"name":"OptOutCooldown","type":"error"},{"inputs":[{"internalType":"uint8","name":"bits","type":"uint8"},{"internalType":"uint256","name":"value","type":"uint256"}],"name":"SafeCastOverflowedUintDowncast","type":"error"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"who","type":"address"},{"indexed":true,"internalType":"address","name":"where","type":"address"}],"name":"OptIn","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"who","type":"address"},{"indexed":true,"internalType":"address","name":"where","type":"address"}],"name":"OptOut","type":"event"},{"inputs":[],"name":"WHERE_REGISTRY","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"WHO_REGISTRY","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"who","type":"address"},{"internalType":"address","name":"where","type":"address"}],"name":"isOptedIn","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"who","type":"address"},{"internalType":"address","name":"where","type":"address"},{"internalType":"uint48","name":"timestamp","type":"uint48"},{"internalType":"bytes","name":"hint","type":"bytes"}],"name":"isOptedInAt","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"where","type":"address"}],"name":"optIn","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"where","type":"address"}],"name":"optOut","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"target","type":"address"},{"internalType":"bytes","name":"data","type":"bytes"}],"name":"staticDelegateCall","outputs":[],"stateMutability":"nonpayable","type":"function"}]',
        "op_net_opt_in": '[{"inputs":[{"internalType":"address","name":"whoRegistry","type":"address"},{"internalType":"address","name":"whereRegistry","type":"address"}],"stateMutability":"nonpayable","type":"constructor"},{"inputs":[],"name":"AlreadyOptedIn","type":"error"},{"inputs":[],"name":"CheckpointUnorderedInsertion","type":"error"},{"inputs":[],"name":"NotOptedIn","type":"error"},{"inputs":[],"name":"NotWhereEntity","type":"error"},{"inputs":[],"name":"NotWho","type":"error"},{"inputs":[],"name":"OptOutCooldown","type":"error"},{"inputs":[{"internalType":"uint8","name":"bits","type":"uint8"},{"internalType":"uint256","name":"value","type":"uint256"}],"name":"SafeCastOverflowedUintDowncast","type":"error"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"who","type":"address"},{"indexed":true,"internalType":"address","name":"where","type":"address"}],"name":"OptIn","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"who","type":"address"},{"indexed":true,"internalType":"address","name":"where","type":"address"}],"name":"OptOut","type":"event"},{"inputs":[],"name":"WHERE_REGISTRY","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"WHO_REGISTRY","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"who","type":"address"},{"internalType":"address","name":"where","type":"address"}],"name":"isOptedIn","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"who","type":"address"},{"internalType":"address","name":"where","type":"address"},{"internalType":"uint48","name":"timestamp","type":"uint48"},{"internalType":"bytes","name":"hint","type":"bytes"}],"name":"isOptedInAt","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"where","type":"address"}],"name":"optIn","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"where","type":"address"}],"name":"optOut","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"target","type":"address"},{"internalType":"bytes","name":"data","type":"bytes"}],"name":"staticDelegateCall","outputs":[],"stateMutability":"nonpayable","type":"function"}]',
        "middleware_service": '[{"inputs":[{"internalType":"address","name":"networkRegistry","type":"address"}],"stateMutability":"nonpayable","type":"constructor"},{"inputs":[],"name":"AlreadySet","type":"error"},{"inputs":[],"name":"NotNetwork","type":"error"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"network","type":"address"},{"indexed":false,"internalType":"address","name":"middleware","type":"address"}],"name":"SetMiddleware","type":"event"},{"inputs":[],"name":"NETWORK_REGISTRY","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"network","type":"address"}],"name":"middleware","outputs":[{"internalType":"address","name":"value","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"middleware_","type":"address"}],"name":"setMiddleware","outputs":[],"stateMutability":"nonpayable","type":"function"}]',
        "vault_factory": '[{"inputs":[{"internalType":"address","name":"owner_","type":"address"}],"stateMutability":"nonpayable","type":"constructor"},{"inputs":[],"name":"AlreadyWhitelisted","type":"error"},{"inputs":[],"name":"EntityNotExist","type":"error"},{"inputs":[],"name":"InvalidImplementation","type":"error"},{"inputs":[],"name":"InvalidVersion","type":"error"},{"inputs":[],"name":"NotOwner","type":"error"},{"inputs":[],"name":"OldVersion","type":"error"},{"inputs":[{"internalType":"address","name":"owner","type":"address"}],"name":"OwnableInvalidOwner","type":"error"},{"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"OwnableUnauthorizedAccount","type":"error"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"entity","type":"address"}],"name":"AddEntity","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"entity","type":"address"},{"indexed":false,"internalType":"uint64","name":"newVersion","type":"uint64"}],"name":"Migrate","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"previousOwner","type":"address"},{"indexed":true,"internalType":"address","name":"newOwner","type":"address"}],"name":"OwnershipTransferred","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"implementation","type":"address"}],"name":"Whitelist","type":"event"},{"inputs":[{"internalType":"uint64","name":"version","type":"uint64"},{"internalType":"address","name":"owner_","type":"address"},{"internalType":"bool","name":"withInitialize","type":"bool"},{"internalType":"bytes","name":"data","type":"bytes"}],"name":"create","outputs":[{"internalType":"address","name":"entity_","type":"address"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint256","name":"index","type":"uint256"}],"name":"entity","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint64","name":"version","type":"uint64"}],"name":"implementation","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"entity_","type":"address"}],"name":"isEntity","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"lastVersion","outputs":[{"internalType":"uint64","name":"","type":"uint64"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"entity_","type":"address"},{"internalType":"uint64","name":"newVersion","type":"uint64"},{"internalType":"bytes","name":"data","type":"bytes"}],"name":"migrate","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"owner","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"renounceOwnership","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"totalEntities","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"newOwner","type":"address"}],"name":"transferOwnership","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"implementation_","type":"address"}],"name":"whitelist","outputs":[],"stateMutability":"nonpayable","type":"function"}]',
    }

    ADDRESSES = {
        "op_registry": "0xa02C55a6306c859517A064fb34d48DFB773A4a52",
        "net_registry": "0x5dEA088d2Be1473d948895cc26104bcf103CEf3E",
        "op_vault_opt_in": "0x63E459f3E2d8F7f5E4AdBA55DE6c50CbB43dD563",
        "op_net_opt_in": "0x973ba45986FF71742129d23C4138bb3fAd4f13A5",
        "middleware_service": "0x70818a53ddE5c2e78Edfb6f6b277Be9a71fa894E",
        "vault_factory": "0x5035c15F3cb4364CF2cF35ca53E3d6FC45FC8899",
    }

    DELEGATOR_TYPES = {
        0: "NetworkRestake",
        1: "FullRestake",
    }

    SLASHER_TYPES = {
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
        meta = {"symbol": res[0], "decimals": int(res[1])}
        self._cache["token_meta"][token] = meta
        return meta

    def get_middleware(self, net):
        return (
            self.contracts["middleware_service"]
            .functions.middleware(self.normalize_address(net))
            .call()
        )

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

    def print_indented(self, *args, indent=2):
        print(" " * indent + " ".join(map(str, args)))


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
            f'Delegator: {vault["delegator"]} ({ctx.obj.DELEGATOR_TYPES.get(vault["delegator_type"], "Unknown")})',
            indent=4,
        )
        slasher_type = ctx.obj.SLASHER_TYPES.get(vault["slasher_type"], "Unknown")
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
                    f'Type: {ctx.obj.DELEGATOR_TYPES[vault["delegator_type"]]} / {ctx.obj.SLASHER_TYPES[vault["slasher_type"]]}',
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
                    f'Type: {ctx.obj.DELEGATOR_TYPES[vault["delegator_type"]]} / {ctx.obj.SLASHER_TYPES[vault["slasher_type"]]}',
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


if __name__ == "__main__":
    cli()
