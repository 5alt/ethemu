import binascii
from Crypto.Hash import keccak
import sys

from octopus.platforms.ETH.disassembler import EthereumDisassembler

from vmstate import EthereumVMstate
from ethvm import EthereumVM


class EthereumEmulatorEngine():

    def __init__(self, bytecode, callcode):
        # retrive instructions, basicblocks & functions statically
        self.callcode = callcode
        self.bytecode = bytecode
        disasm = EthereumDisassembler(binascii.hexlify(bytecode).decode())
        self.instructions = disasm.disassemble()
        self.reverse_instructions = {k: v for k, v in enumerate(self.instructions)}
        self.vm = EthereumVM()

 
    def emulate(self, state=EthereumVMstate(), depth=0):
        
        # get current instruction
        instr = self.reverse_instructions[state.pc]

        # halt variable use to catch ending branch
        halt = False
        while not halt:
            # get current instruction
            instr = self.reverse_instructions[state.pc]

            # Save instruction and state
            state.instr = instr
            state.pc += 1
            print(hex(instr.offset), instr.name, hex(instr.operand_interpretation) if instr.operand_interpretation is not None else '')
            # execute single instruction
            halt = self.emulate_one_instruction(instr, state, depth)
            if halt: break


    def emulate_one_instruction(self, instr, state, depth):

        halt = False

        #
        #  0s: Stop and Arithmetic Operations
        #
        if instr.name == 'STOP':
            halt = True
        elif instr.is_arithmetic:
            self.emul_arithmetic_instruction(instr, state)
        #
        #  10s: Comparison & Bitwise Logic Operations
        #
        elif instr.is_comparaison_logic:
            self.emul_comparaison_logic_instruction(instr, state)
        #
        #  20s: SHA3
        #
        elif instr.is_sha3:
            self.emul_sha3_instruction(instr, state)
        #
        #  30s: Environment Information
        #
        elif instr.is_environmental:
            halt = self.environmental_instruction(instr, state)
        #
        #  40s: Block Information
        #
        elif instr.uses_block_info:
            self.block_instruction(instr, state)
        #
        #  50s: Stack, Memory, Storage, and Flow Information
        #
        elif instr.uses_stack_block_storage_info:
            halt = self.stack_memory_storage_flow_instruction(instr, state, depth)
        #
        #  60s & 70s: Push Operations
        #
        elif instr.name.startswith("PUSH"):
            value = int.from_bytes(instr.operand, byteorder='big')
            #print(instr.operand)
            state.stack.append(value)
        #
        #  80s: Duplication Operations
        #
        elif instr.name.startswith('DUP'):
            # DUPn (eg. DUP1: a b c -> a b c c, DUP3: a b c -> a b c a)
            position = instr.pops  # == XX from DUPXX
            state.stack.append(state.stack[- position])
        #
        #  90s: Swap Operations
        #
        elif instr.name.startswith('SWAP'):
            # SWAPn (eg. SWAP1: a b c d -> a b d c, SWAP3: a b c d -> d b c a)
            position = instr.pops - 1  # == XX from SWAPXX
            temp = state.stack[-position - 1]
            state.stack[-position - 1] = state.stack[-1]
            state.stack[-1] = temp
            
        #
        #  a0s: Logging Operations
        #
        elif instr.name.startswith('LOG'):
            # only stack operations emulated
            print("LOG: ", instr.name, instr.operand)
            #state.stack.append(instr)
        #
        #  f0s: System Operations
        #
        elif instr.is_system:
            halt = self.system_instruction(instr, state)
            #ssa.append(instr.name)

        # UNKNOWN INSTRUCTION
        else:
            print('UNKNOWN = ' + instr.name)
            halt = True


        return halt

    def emul_arithmetic_instruction(self, instr, state):

        if instr.name in ['ADD', 'SUB', 'MUL', 'DIV', 'MOD', 'SDIV', 'SMOD', 'EXP', 'SIGNEXTEND']:
            args = [state.stack.pop(), state.stack.pop()]
            args = map(lambda x:int(x.hex(),16) if type(x) == type(b'') else x, args)

        elif instr.name in ['ADDMOD', 'MULMOD']:
            args = [state.stack.pop(), state.stack.pop(), state.stack.pop()]
            args = map(lambda x:int(x.hex(),16) if type(x) == type(b'') else x, args)

        self.vm.dispatcher(instr, args, state)

    def emul_comparaison_logic_instruction(self, instr, state):

        if instr.name in ['LT', 'GT', 'SLT', 'SGT',
                          'EQ', 'AND', 'OR', 'XOR', 'BYTE']:
            args = [state.stack.pop(), state.stack.pop()]
            args = map(lambda x:int(x.hex(),16) if type(x) == type(b'') else x, args)
        elif instr.name in ['ISZERO', 'NOT']:
            args = [state.stack.pop()]
            args = map(lambda x:int(x.hex(),16) if type(x) == type(b'') else x, args)

        self.vm.dispatcher(instr, args, state)


    def emul_sha3_instruction(self, instr, state):
        s0, s1 = state.stack.pop(), state.stack.pop()
        result = keccak.new(data=b''.join(state.memory[s0: s0+s1]), digest_bits=256).digest()
        state.stack.append(result)

    def environmental_instruction(self, instr, state):
        halt = False

        if instr.name == 'CALLDATASIZE':
            state.stack.append(len(self.callcode))

        elif instr.name == 'CODESIZE':
            state.stack.append(len(self.bytecode))

        elif instr.name == 'CALLDATALOAD':
            s0 = state.stack.pop()
            state.stack.append(self.callcode[s0: s0+32])

        elif instr.name == 'CALLDATACOPY':
            op0, op1, op2 = state.stack.pop(), state.stack.pop(), state.stack.pop()
            state.mem_store(op0, self.callcode[op1: op1+op2])

        elif instr.name == 'CODECOPY':
            op0, op1, op2 = state.stack.pop(), state.stack.pop(), state.stack.pop()
            state.mem_store(op0, self.bytecode[op1: op1+op2])

        elif instr.name in ['RETURNDATASIZE']:
            value = 0
            state.stack.append(value)
            
        elif instr.name in ['EXTCODESIZE']:
            s0 = state.stack.pop()
            value = 0x01
            state.stack.append(value)

        elif instr.name in ['RETURNDATACOPY']:
            op0, op1, op2 = state.stack.pop(), state.stack.pop(), state.stack.pop()
            halt = True

        elif instr.name == 'EXTCODECOPY':
            addr = state.stack.pop()
            start, s2, size = state.stack.pop(), state.stack.pop(), state.stack.pop()
            #state.stack.append(instr)
            halt = True
        else:
            halt = self.vm.dispatcher(instr, [], state)

        return halt

    def block_instruction(self, instr, state):

        if instr.name == 'BLOCKHASH':
            blocknumber = state.stack.pop()

        elif instr.name in ['COINBASE', 'TIMESTAMP', 'NUMBER', 'DIFFICULTY', 'GASLIMIT']:
            pass

        self.vm.dispatcher(instr, [], state)

    def stack_memory_storage_flow_instruction(self, instr, state, depth):

        byte2int = lambda x:int(x.hex(),16) if type(x) == type(b'') else x
        int2byte = lambda x,y:x.to_bytes(y, byteorder="big") if type(x) == type(1) else x

        halt = False
        op = instr.name

        if op == 'POP':
            s0 = state.stack.pop()

        elif op == 'MLOAD':
            s0 = state.stack.pop()
            s0 = byte2int(s0)
            state.stack.append(state.mem_load(s0, 32))

        elif op == 'SLOAD':
            s0 = state.stack.pop()
            state.stack.append(state.storage.get(s0, 0))

        elif op == 'SSTORE':
            s0, s1 = state.stack.pop(), state.stack.pop()
            state.storage[s0] = s1

        elif op == 'MSTORE':
            s0, s1 = state.stack.pop(), state.stack.pop()
            s0 = byte2int(s0)
            s1 = int2byte(s1, 32)
            state.mem_store(s0, s1)

        elif op == 'MSTORE8':
            s0, s1 = state.stack.pop(), state.stack.pop()
            s0 = byte2int(s0)
            s1 = int2byte(s1, 1)
            state.mem_store(s0, s1)

        elif op == 'JUMP':
            jump_addr = state.stack.pop()
            target = next(filter(lambda element: element.offset == jump_addr, self.instructions))
            state.pc = self.instructions.index(target)

            if target.name != "JUMPDEST":
                logger.info('[X] Bad JUMP to 0x%x' % jump_addr)
                return True

        elif op == 'JUMPI':
            jump_addr, condition = state.stack.pop(), state.stack.pop()
            if condition:
                target = next(filter(lambda element: element.offset == jump_addr, self.instructions))
                state.pc = self.instructions.index(target)

                if target.name != "JUMPDEST":
                    logger.info('[X] Bad JUMP to 0x%x' % jump_addr)
                    return True

        elif op == 'PC':
            state.stack.append(instr.offset)

        elif op == 'MSIZE':
            state.stack.append(len(state.memory))

        elif op == 'GAS':
            state.stack.append(0x1337)

        elif op == 'JUMPDEST':
            pass

        return halt

    def system_instruction(self, instr, state):

        halt = False

        if instr.name == 'CREATE':
            args = [state.stack.pop(), state.stack.pop(), state.stack.pop()]
            halt = True
            
        elif instr.name in ('CALL', 'CALLCODE', 'DELEGATECALL', 'STATICCALL'):

            if instr.name in ('CALL', 'CALLCODE'):
                gas, to, value, meminstart, meminsz, memoutstart, memoutsz = \
                    state.stack.pop(), state.stack.pop(), state.stack.pop(), state.stack.pop(), state.stack.pop(), state.stack.pop(), state.stack.pop()
                args = [gas, to, value, meminstart, meminsz, memoutstart, memoutsz]

            else:
                gas, to, meminstart, meminsz, memoutstart, memoutsz = \
                    state.stack.pop(), state.stack.pop(), state.stack.pop(), state.stack.pop(), state.stack.pop(), state.stack.pop()
                args = [gas, to, meminstart, meminsz, memoutstart, memoutsz]

            halt = True

        elif instr.name in ['RETURN', 'REVERT']:
            halt = True

        elif instr.name in ['INVALID', 'SELFDESTRUCT']:
            halt = True

        return halt

