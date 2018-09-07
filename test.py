import binascii
from ethemu import EthereumEmulatorEngine
from vmstate import EthereumVMstate

bytecode = binascii.unhexlify('60806040526004361061004b5763ffffffff7c0100000000000000000000000000000000000000000000000000000000600035041663c6c58bcd811461004d578063fc0e74d1146100da575b005b34801561005957600080fd5b506100656004356100ef565b6040805160208082528351818301528351919283929083019185019080838360005b8381101561009f578181015183820152602001610087565b50505050905090810190601f1680156100cc5780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b3480156100e657600080fd5b5061004b6101af565b60015460609082187c010000000000000000000000000000000000000000000000000000000080820463666c6167141561017157336000908152600360209081526040918290208690558151808301909252600a82527f666c6167207361766564000000000000000000000000000000000000000000009082015292506101a8565b60408051808201909152600c81527f666f726d6174206572726f720000000000000000000000000000000000000000602082015292505b5050919050565b60005473ffffffffffffffffffffffffffffffffffffffff1633146101d357600080fd5b7f616161616161616161616161616161616161616161616161616161616161616160015560005473ffffffffffffffffffffffffffffffffffffffff16ff00a165627a7a7230582073e7ac2ceb4e10aa1ca14495668f62cac1d13091ab09eb2e923ae05edf1859130029')
callcode = binascii.unhexlify('c6c58bcd95529edd28cb526ab5071fd2fdebd5fc4e08b2af6876dd33a57764a970157576')

state = EthereumVMstate()
state.storage = {1: 0}
evm = EthereumEmulatorEngine(bytecode=bytecode, callcode=callcode)
evm.emulate()