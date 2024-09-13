import click
from web3 import Web3
from w3multicall.multicall import W3Multicall

ABIS = {
    'op_registry': '[{"inputs":[],"name":"EntityNotExist","type":"error"},{"inputs":[],"name":"OperatorAlreadyRegistered","type":"error"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"entity","type":"address"}],"name":"AddEntity","type":"event"},{"inputs":[{"internalType":"uint256","name":"index","type":"uint256"}],"name":"entity","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"entity_","type":"address"}],"name":"isEntity","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"registerOperator","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"totalEntities","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"}]',
    'net_registry': '[{"inputs":[],"name":"EntityNotExist","type":"error"},{"inputs":[],"name":"OperatorAlreadyRegistered","type":"error"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"entity","type":"address"}],"name":"AddEntity","type":"event"},{"inputs":[{"internalType":"uint256","name":"index","type":"uint256"}],"name":"entity","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"entity_","type":"address"}],"name":"isEntity","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"registerOperator","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"totalEntities","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"}]',
    'op_vault_opt_in': '[{"inputs":[{"internalType":"address","name":"whoRegistry","type":"address"},{"internalType":"address","name":"whereRegistry","type":"address"}],"stateMutability":"nonpayable","type":"constructor"},{"inputs":[],"name":"AlreadyOptedIn","type":"error"},{"inputs":[],"name":"CheckpointUnorderedInsertion","type":"error"},{"inputs":[],"name":"NotOptedIn","type":"error"},{"inputs":[],"name":"NotWhereEntity","type":"error"},{"inputs":[],"name":"NotWho","type":"error"},{"inputs":[],"name":"OptOutCooldown","type":"error"},{"inputs":[{"internalType":"uint8","name":"bits","type":"uint8"},{"internalType":"uint256","name":"value","type":"uint256"}],"name":"SafeCastOverflowedUintDowncast","type":"error"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"who","type":"address"},{"indexed":true,"internalType":"address","name":"where","type":"address"}],"name":"OptIn","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"who","type":"address"},{"indexed":true,"internalType":"address","name":"where","type":"address"}],"name":"OptOut","type":"event"},{"inputs":[],"name":"WHERE_REGISTRY","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"WHO_REGISTRY","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"who","type":"address"},{"internalType":"address","name":"where","type":"address"}],"name":"isOptedIn","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"who","type":"address"},{"internalType":"address","name":"where","type":"address"},{"internalType":"uint48","name":"timestamp","type":"uint48"},{"internalType":"bytes","name":"hint","type":"bytes"}],"name":"isOptedInAt","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"where","type":"address"}],"name":"optIn","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"where","type":"address"}],"name":"optOut","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"target","type":"address"},{"internalType":"bytes","name":"data","type":"bytes"}],"name":"staticDelegateCall","outputs":[],"stateMutability":"nonpayable","type":"function"}]',
    'op_net_opt_in': '[{"inputs":[{"internalType":"address","name":"whoRegistry","type":"address"},{"internalType":"address","name":"whereRegistry","type":"address"}],"stateMutability":"nonpayable","type":"constructor"},{"inputs":[],"name":"AlreadyOptedIn","type":"error"},{"inputs":[],"name":"CheckpointUnorderedInsertion","type":"error"},{"inputs":[],"name":"NotOptedIn","type":"error"},{"inputs":[],"name":"NotWhereEntity","type":"error"},{"inputs":[],"name":"NotWho","type":"error"},{"inputs":[],"name":"OptOutCooldown","type":"error"},{"inputs":[{"internalType":"uint8","name":"bits","type":"uint8"},{"internalType":"uint256","name":"value","type":"uint256"}],"name":"SafeCastOverflowedUintDowncast","type":"error"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"who","type":"address"},{"indexed":true,"internalType":"address","name":"where","type":"address"}],"name":"OptIn","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"who","type":"address"},{"indexed":true,"internalType":"address","name":"where","type":"address"}],"name":"OptOut","type":"event"},{"inputs":[],"name":"WHERE_REGISTRY","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"WHO_REGISTRY","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"who","type":"address"},{"internalType":"address","name":"where","type":"address"}],"name":"isOptedIn","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"who","type":"address"},{"internalType":"address","name":"where","type":"address"},{"internalType":"uint48","name":"timestamp","type":"uint48"},{"internalType":"bytes","name":"hint","type":"bytes"}],"name":"isOptedInAt","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"where","type":"address"}],"name":"optIn","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"where","type":"address"}],"name":"optOut","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"target","type":"address"},{"internalType":"bytes","name":"data","type":"bytes"}],"name":"staticDelegateCall","outputs":[],"stateMutability":"nonpayable","type":"function"}]',
    'middleware_service': '[{"inputs":[{"internalType":"address","name":"networkRegistry","type":"address"}],"stateMutability":"nonpayable","type":"constructor"},{"inputs":[],"name":"AlreadySet","type":"error"},{"inputs":[],"name":"NotNetwork","type":"error"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"network","type":"address"},{"indexed":false,"internalType":"address","name":"middleware","type":"address"}],"name":"SetMiddleware","type":"event"},{"inputs":[],"name":"NETWORK_REGISTRY","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"network","type":"address"}],"name":"middleware","outputs":[{"internalType":"address","name":"value","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"middleware_","type":"address"}],"name":"setMiddleware","outputs":[],"stateMutability":"nonpayable","type":"function"}]',
    'vault_factory': '[{"inputs":[{"internalType":"address","name":"owner_","type":"address"}],"stateMutability":"nonpayable","type":"constructor"},{"inputs":[],"name":"AlreadyWhitelisted","type":"error"},{"inputs":[],"name":"EntityNotExist","type":"error"},{"inputs":[],"name":"InvalidImplementation","type":"error"},{"inputs":[],"name":"InvalidVersion","type":"error"},{"inputs":[],"name":"NotOwner","type":"error"},{"inputs":[],"name":"OldVersion","type":"error"},{"inputs":[{"internalType":"address","name":"owner","type":"address"}],"name":"OwnableInvalidOwner","type":"error"},{"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"OwnableUnauthorizedAccount","type":"error"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"entity","type":"address"}],"name":"AddEntity","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"entity","type":"address"},{"indexed":false,"internalType":"uint64","name":"newVersion","type":"uint64"}],"name":"Migrate","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"previousOwner","type":"address"},{"indexed":true,"internalType":"address","name":"newOwner","type":"address"}],"name":"OwnershipTransferred","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"implementation","type":"address"}],"name":"Whitelist","type":"event"},{"inputs":[{"internalType":"uint64","name":"version","type":"uint64"},{"internalType":"address","name":"owner_","type":"address"},{"internalType":"bool","name":"withInitialize","type":"bool"},{"internalType":"bytes","name":"data","type":"bytes"}],"name":"create","outputs":[{"internalType":"address","name":"entity_","type":"address"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint256","name":"index","type":"uint256"}],"name":"entity","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint64","name":"version","type":"uint64"}],"name":"implementation","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"entity_","type":"address"}],"name":"isEntity","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"lastVersion","outputs":[{"internalType":"uint64","name":"","type":"uint64"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"entity_","type":"address"},{"internalType":"uint64","name":"newVersion","type":"uint64"},{"internalType":"bytes","name":"data","type":"bytes"}],"name":"migrate","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"owner","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"renounceOwnership","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"totalEntities","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"newOwner","type":"address"}],"name":"transferOwnership","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"implementation_","type":"address"}],"name":"whitelist","outputs":[],"stateMutability":"nonpayable","type":"function"}]',
}

ADDRESSES = {
    'op_registry': '0xa02C55a6306c859517A064fb34d48DFB773A4a52',
    'net_registry': '0x5dEA088d2Be1473d948895cc26104bcf103CEf3E',
    'op_vault_opt_in': '0x63E459f3E2d8F7f5E4AdBA55DE6c50CbB43dD563',
    'op_net_opt_in': '0x973ba45986FF71742129d23C4138bb3fAd4f13A5',
    'middleware_service': '0x70818a53ddE5c2e78Edfb6f6b277Be9a71fa894E',
    'vault_factory': '0x5035c15F3cb4364CF2cF35ca53E3d6FC45FC8899',
}

CONTRACTS = {}

PROVIDER = 'https://ethereum-holesky-rpc.publicnode.com'
W3 = None

_CACHE = {
    'token_meta': {},
}

def normalize_address(address):
    return Web3.to_checksum_address(address)

def init():
    global W3
    W3 = Web3(Web3.HTTPProvider(PROVIDER))
    for contract in ADDRESSES:
        CONTRACTS[contract] = W3.eth.contract(address=ADDRESSES[contract], abi=ABIS[contract])

def get_token_meta(token):
    if token in _CACHE['token_meta']:
        return _CACHE['token_meta'][token]
    w3_multicall = W3Multicall(W3)
    w3_multicall.add(W3Multicall.Call(
        normalize_address(token),
        'symbol()(string)'
    ))
    w3_multicall.add(W3Multicall.Call(
        normalize_address(token),
        'decimals()(uint8)'
    ))
    res = w3_multicall.call()
    meta = {
        "symbol": res[0],
        "decimals": int(res[1])
    }
    _CACHE['token_meta'][token] = meta
    return meta

def get_middleware(net):
    return CONTRACTS['middleware_service'].functions.middleware(normalize_address(net)).call()

def get_nets():
    total_entities = CONTRACTS['net_registry'].functions.totalEntities().call()
    w3_multicall = W3Multicall(W3)
    for i in range(total_entities):
        w3_multicall.add(W3Multicall.Call(
            ADDRESSES['net_registry'],
            'entity(uint256)(address)',
            i
        ))
    nets = w3_multicall.call()

    w3_multicall = W3Multicall(W3)
    for net in nets:
        w3_multicall.add(W3Multicall.Call(
            ADDRESSES['middleware_service'],
            'middleware(address)(address)',
            net
        ))
    
    middlewares = w3_multicall.call()

    results = []
    for i in range(len(nets)):
        results.append({
            'net': nets[i],
            'middleware': middlewares[i]
        })
    return results

def get_ops():
    total_entities = CONTRACTS['op_registry'].functions.totalEntities().call()
    w3_multicall = W3Multicall(W3)
    for i in range(total_entities):
        w3_multicall.add(W3Multicall.Call(
            ADDRESSES['op_registry'],
            'entity(uint256)(address)',
            i
        ))
    ops = w3_multicall.call()
    return ops

def get_op_nets(operator):
    nets = get_nets()
    w3_multicall = W3Multicall(W3)
    for net in nets:
        w3_multicall.add(W3Multicall.Call(
            ADDRESSES['op_net_opt_in'],
            'isOptedIn(address,address)(bool)',
            [operator, net['net']]
        ))
    optins = w3_multicall.call()

    results = []
    for i in range(len(optins)):
        if optins[i]:
            results.append({
                'net': nets[i]['net'],
                'middleware': nets[i]['middleware']
            })
    return results

def get_net_ops(net):
    ops = get_ops()
    w3_multicall = W3Multicall(W3)
    for op in ops:
        w3_multicall.add(W3Multicall.Call(
            ADDRESSES['op_net_opt_in'],
            'isOptedIn(address,address)(bool)',
            [op, net]
        ))
    optins = w3_multicall.call()

    results = []
    for i in range(len(optins)):
        if optins[i]:
            results.append(ops[i])
    return results

def get_vaults():
    total_entities = CONTRACTS['vault_factory'].functions.totalEntities().call()
    w3_multicall = W3Multicall(W3)
    for i in range(total_entities):
        w3_multicall.add(W3Multicall.Call(
            ADDRESSES['vault_factory'],
            'entity(uint256)(address)',
            i
        ))
    vaults = w3_multicall.call()

    w3_multicall = W3Multicall(W3)
    for vault in vaults:
        w3_multicall.add(W3Multicall.Call(
            vault,
            'collateral()(address)'
        ))
        w3_multicall.add(W3Multicall.Call(
            vault,
            'delegator()(address)'
        ))
        w3_multicall.add(W3Multicall.Call(
            vault,
            'slasher()(address)'
        ))
    
    collaterals = w3_multicall.call()

    results = []
    for i in range(len(vaults)):
        results.append({
            'vault': vaults[i],
            'collateral': collaterals[3 * i],
            'delegator': collaterals[3 * i + 1],
            'slasher': collaterals[3 * i + 2]
        })
    return results

def get_net_vaults(net):
    vaults = get_vaults()
    w3_multicall = W3Multicall(W3)
    for vault in vaults:
        w3_multicall.add(W3Multicall.Call(
            vault['delegator'],
            'networkLimit(bytes32)(uint256)',
            bytes.fromhex(net[2:])
        ))

    limits = w3_multicall.call()

    results = []
    for i in range(len(limits)):
        if limits[i] > 0:
            results.append(vaults[i])
            results[-1]['limit'] = limits[i]
    return results

def get_net_ops_vaults(net):
    vaults = get_net_vaults(net)
    ops = get_net_ops(net)

    w3_multicall = W3Multicall(W3)
    for op in ops:
        for vault in vaults:
            w3_multicall.add(W3Multicall.Call(
                vault['delegator'],
                'stake(bytes32,address)(uint256)',
                [bytes.fromhex(net[2:]), op] # TODO: fix subnets
            ))

    stakes = w3_multicall.call()
    results = [ {'op': op, 'vaults': []} for op in ops ]
    i = 0
    for op_idx in range(len(ops)):
        for vault in vaults:
            if stakes[i] > 0:
                vault['stake'] = stakes[i]
                results[op_idx]['vaults'].append(vault)
            i += 1

    return results

def get_op_nets_vaults(op):
    nets = get_op_nets(op)

    w3_multicall = W3Multicall(W3)
    net_vaults = {}
    rev_vaults = []
    i = 0
    for net in nets:
        net_vaults[net['net']] = get_net_vaults(net['net'])
        for vault in net_vaults[net['net']]:
            w3_multicall.add(W3Multicall.Call(
                vault['delegator'],
                'stake(bytes32,address)(uint256)',
                [bytes.fromhex(net['net'][2:]), op] # TODO: fix subnets
            ))
            rev_vaults.append((net['net'], vault))

    stakes = w3_multicall.call()

    results = [ {'net': net['net'], 'vaults': []} for net in nets ]
    i = 0
    for net_idx in range(len(nets)):
        for vault in net_vaults[nets[net_idx]['net']]:
            if stakes[i] > 0:
                vault['stake'] = stakes[i]
                results[net_idx]['vaults'].append(vault)
            i += 1

    return results


@click.group()
@click.option('--provider', default=PROVIDER, help='Ethereum provider URL [http(s)]')
def cli(provider):
    global PROVIDER
    PROVIDER = provider
    init()

@cli.command()
@click.argument('address')
def isop(address):
    """Check if address is operator"""
    address = normalize_address(address)
    print (CONTRACTS['op_registry'].functions.isEntity(address).call())

@cli.command()
@click.argument('address')
def isnet(address):
    """Check if address is network"""
    address = normalize_address(address)
    print (CONTRACTS['net_registry'].functions.isEntity(address).call())

@cli.command()
@click.argument('address')
def middleware(address):
    """Get network middleware address"""
    address = normalize_address(address)
    print (CONTRACTS['middleware_service'].functions.middleware(address).call())

@cli.command()
def nets():
    """List all networks"""
    nets = get_nets()
    print (f'All networks [{len(nets)} total]:')
    for net in nets:
        print (f'  Network: {net["net"]}')
        print (f'    Middleware: {net["middleware"]}\n')

@cli.command()
def ops():
    """List all operators"""
    ops = get_ops()
    print (f'All operators [{len(ops)} total]:')
    for op in ops:
        print (f'  Operator: {op}')

@cli.command()
def vaults():
    """List all vaults"""
    vaults = get_vaults()
    print (f'All vaults [{len(vaults)} total]:')
    for vault in vaults:
        print (f'  Vault: {vault["vault"]}')
        print (f'    Collateral: {vault["collateral"]} ({get_token_meta(vault["collateral"])["symbol"]})')
        print (f'    Delegator: {vault["delegator"]}')
        print (f'    Slasher: {vault["slasher"]}\n')

@cli.command()
@click.argument('address')
def opnets(address):
    """List all networks operator is opted in"""
    address = normalize_address(address)
    print (f'Operator: {address}')

    nets = get_op_nets(address)
    print (f'Networks [{len(nets)} total]:')
    for net in nets:
        print (f'  Network: {net["net"]}')

@cli.command()
@click.argument('address')
def netops(address):
    """List all operators opted in network"""
    address = normalize_address(address)
    print (f'Network: {address}')

    ops = get_net_ops(address)
    print (f'Operators [{len(ops)} total]:')
    for op in ops:
        print (f'  Operator: {op}')

@cli.command()
@click.argument('address')
def netstakes(address):
    """Show stakes of all operators in network"""
    address = normalize_address(address)
    print (f'Network: {address}')
    print (f'Middleware: {get_middleware(address)}')

    opsvaults = get_net_ops_vaults(address)
    print (f'Operators [{len(opsvaults)} total]:')
    total_stakes = {}
    for op in opsvaults:
        print (f'  Operator: {op["op"]}')
        collaterals = {}
        for vault in op['vaults']:
            vault["token_meta"] = get_token_meta(vault["collateral"])
            if vault["collateral"] not in collaterals:
                collaterals[vault["collateral"]] = []
            collaterals[vault["collateral"]].append(vault)

        total_op_stake = ''
        for collateral in collaterals.keys():
            stakes_sum = 0
            token_meta = get_token_meta(collateral)
            print (f'    Collateral: {collateral} ({token_meta["symbol"]})')
            for vault in collaterals[collateral]:
                print (f'      Vault: {vault["vault"]} Stake: {vault["stake"] / 10**token_meta["decimals"]}')
                stakes_sum += vault["stake"]
            total_op_stake += f'{stakes_sum / 10**token_meta["decimals"]} {token_meta["symbol"]} + '
            if collateral not in total_stakes:
                total_stakes[collateral] = 0
            total_stakes[collateral] += stakes_sum

        if total_op_stake:
            print('    Total stake:', total_op_stake[:-3])
        else:
            print('    Total stake: 0')
        print('')

    print('Total stakes:')
    for collateral in total_stakes.keys():
        token_meta = get_token_meta(collateral)
        print(f'  Collateral {collateral} ({token_meta["symbol"]}): {total_stakes[collateral] / 10**token_meta["decimals"]}')

@cli.command()
@click.argument('address')
def opstakes(address):
    """Show operator stakes in all networks"""
    address = normalize_address(address)
    print (f'Operator: {address}')

    netsvaults = get_op_nets_vaults(address)
    print (f'Networks [{len(netsvaults)} total]:')
    total_stakes = {}
    for net in netsvaults:
        print (f'  Network: {net["net"]}')
        collaterals = {}
        for vault in net['vaults']:
            vault["token_meta"] = get_token_meta(vault["collateral"])
            if vault["collateral"] not in collaterals:
                collaterals[vault["collateral"]] = []
            collaterals[vault["collateral"]].append(vault)

        total_net_stake = ''
        for collateral in collaterals.keys():
            stakes_sum = 0
            token_meta = get_token_meta(collateral)
            print (f'    Collateral: {collateral} ({token_meta["symbol"]})')
            for vault in collaterals[collateral]:
                print (f'      Vault: {vault["vault"]} Stake: {vault["stake"] / 10**token_meta["decimals"]}')
                stakes_sum += vault["stake"]
            total_net_stake += f'{stakes_sum / 10**token_meta["decimals"]} {token_meta["symbol"]} + '
            if collateral not in total_stakes:
                total_stakes[collateral] = 0
            total_stakes[collateral] += stakes_sum

        if total_net_stake:
            print('    Total stake:', total_net_stake[:-3])
        else:
            print('    Total stake: 0')
        print('')

    print('Total stakes:')
    for collateral in total_stakes.keys():
        token_meta = get_token_meta(collateral)
        print(f'  Collateral {collateral} ({token_meta["symbol"]}): {total_stakes[collateral] / 10**token_meta["decimals"]}')


if __name__ == '__main__':
    cli()

