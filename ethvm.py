from logging import getLogger
logging = getLogger(__name__)

import env

class EthereumVM(object):
    def __init__(self):
        self._dispatch_function = {
            # arithmetic
            'ADD': self.symbolic_add,
            'SUB': self.operate_SUB,
            'MUL': self.operate_MUL,
            'DIV': self.operate_DIV,
            'MOD': self.operate_MOD,
            'SDIV': self.operate_SDIV,
            'SMOD': self.operate_SMOD,
            'ADDMOD': self.operate_ADDMOD,
            'MULMOD': self.operate_MULMOD,
            'EXP': self.operate_EXP,
            'SIGNEXTEND': self.operate_SIGNEXTEND,
            
            # logic
            'LT': self.operate_LT,
            'GT': self.operate_GT,
            'SLT': self.operate_SLT,
            'SGT': self.operate_SGT,
            'EQ': self.operate_EQ,
            'ISZERO': self.operate_ISZERO,
            'AND': self.operate_AND,
            'OR': self.operate_OR,
            'XOR': self.operate_XOR,
            'NOT': self.operate_NOT,
            'BYTE': self.operate_BYTE,
        }

    def dispatcher(self, instr, values, state):

        mnemonic = instr.name
        fn = self._dispatch_function.get(mnemonic, None)
        if fn:
            state.stack.append(fn(*values))
            return False
        elif hasattr(env, mnemonic):
            state.stack.append(getattr(env, mnemonic))
            return False
        return True


    # arithmetics
    def symbolic_add(self, *values):
        return (values[0]+values[1]) % (2**256)

    def operate_SUB(self, *values):
        return (values[0]-values[1]) % (2**256)

    def operate_MUL(self, *values):
        return (values[0]*values[1]) % (2**256)

    def operate_DIV(self, *values):
        if values[1] == 0:
            return 0
        else:
            return int((values[0]/values[1]) % (2**256))

    def operate_MOD(self, *values):
        return 0 if values[1] == 0 else values[0] % values[1]

    def operate_SDIV(self, *values):
        s0, s1 = values[0], values[1]
        sign = -1 if (s0 / s1) < 0 else 1
        computed = sign * (abs(s0) / abs(s1))
        return computed

    def operate_SMOD(self, *values):
        sign = -1 if values[0] < 0 else 1
        computed = sign * (abs(values[0]) % abs(values[1]))
        return computed

    def operate_ADDMOD(self, *values):
        s0, s1, s2 = values[0], values[1], values[2]
        return (s0 + s1) % s2 if s2 else 0

    def operate_MULMOD(self, *values):
        s0, s1, s2 = values[0], values[1], values[2]
        return (s0 * s1) % s2 if s2 else 0

    def operate_EXP(self, *values):
        base, exponent = values[0], values[1]
        return pow(base, exponent)

        # logic
    def operate_LT(self, *values):
        return values[0] < values[1]

    def operate_GT(self, *values):
        return values[0] > values[1]

    def operate_SLT(self, *values):
        return values[0] < values[1]

    def operate_SGT(self, *values):
        return values[0] > values[1]

    def operate_EQ(self, *values):
        return values[0] == values[1]

    def operate_ISZERO(self, *values):
        return values[0] == 0

    def operate_AND(self, *values):
        return values[0] & values[1]

    def operate_OR(self, *values):
        return values[0] | values[1]

    def operate_XOR(self, *values):
        return values[0] ^ values[1]

    def operate_NOT(self, *values):
        return (~values[0]) & (2**256-1)

    def operate_BYTE(self, *values):
        n = values[0]
        x = values[1]
        if type(x) == type(1):
            return (x).to_bytes(32, byteorder="big")[n]
        else:
            return x[n]

    def operate_SIGNEXTEND(self, *values):
        def sign_extend(value, bits):
            sign_bit = 1 << (bits - 1)
            return (value & (sign_bit - 1)) - (value & sign_bit)

        i = values[0]
        x = values[1]
        return ((sign_extend(x,  (i*8+7)) + 2**256) % 2**256 ).to_bytes(32, byteorder="big")

        
