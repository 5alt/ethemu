class EthereumVMstate():

    def __init__(self, gas=1000000):
        self.storage = {}
        self.memory = []
        self.stack = []
        self.pc = 0
        self.instr = None

    def details(self):

        return {'storage': self.storage,
                'memory': self.memory,
                'stack': self.stack,
                'pc': self.pc}


    def mem_store(self, start, data):
        sz = len(data)
        if sz and start + sz > len(self.memory):

                n_append = start + sz - len(self.memory)

                while n_append > 0:
                    self.memory.append(b'\0')
                    n_append -= 1

        for i in range(sz):
            self.memory[start + i] = bytes([data[i]]) if type(data[i]) == type(1) else data[i]


    def mem_load(self, start, sz):
        data = b''
        if sz and start + sz -1 < len(self.memory):
            for i in self.memory[start: start+sz]:
                data += i
            return data
        else:
            raise Exception

