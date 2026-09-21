from ghidra.app.decompiler import DecompileOptions, DecompInterface
from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.pcode import PcodeBlockBasic, PcodeOp, PcodeOpAST
from ghidra.program.model.listing import Instruction
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.database.function import FunctionDB

class PCodeOpComparison():
    def __init__(self, pcodeop):
        assert type(pcodeop) in [PcodeOp, PcodeOpAST], "Input is {} but must be PcodeOp/PcodeOpAST!".format(type(pcodeop))
        self.pcodeop = pcodeop
        self.mnemonic = pcodeop.getMnemonic()
        self.numInputs = pcodeop.getNumInputs()
        self.inputs = pcodeop.getInputs()
        self.inputNames = self.get_input_names()
        
    def get_input_names(self):
        names = []
        for i in self.inputs:
            hvar = i.getHigh()
            hvar_type = hvar.getClass().__name__
            if hvar_type == "HighConstant":
                names.append(str(hvar.getScalar()))
            else:
                names.append(str(hvar.getName()))
        
        return names
                
    def to_string(self):
        if self.numInputs == 2:
            s = "{} {} {}".format(self.inputNames[0], self.mnemonic, self.inputNames[1])
        elif self.numInputs == 1:
            s = "{} {}".format(self.mnemonic, self.inputNames[0])
        else:
            s = self.pcodeop.toString()
        return s

class PCodeBlock:
    ADDR_LEN = len(currentProgram.getMaxAddress().toString())
    
    def __init__(self, pb):
        assert type(pb) == PcodeBlockBasic, "Input is {} but must be PcodeBlockBasic!".format(type(pb))
        self.block = pb
        self.calls = self.get_calls()
        self.address = pb.getStart()
        self.condition = self.get_condition()
        
    def get_calls(self):
        calls = []
        for op in self.block.getIterator():
            if op.getOpcode() in [PcodeOp.CALL, PcodeOp.CALLIND, PcodeOp.CALLOTHER]:
                instruction_address = op.getSeqnum().getTarget()
                instruction = getInstructionAt(instruction_address)
                
                call_info = "{} {}".format(instruction_address, instruction)
                
                call_target = self.get_call_target(op)
                if call_target: 
                    call_info += " ({})".format(call_target)
                    
                calls.append(call_info)
                
        return calls
    
    def get_call_target(self, call):
        if type(call) in [PcodeOp, PcodeOpAST]:
            func_addr = call.inputs[0].getAddress()
            func = getFunctionAt(func_addr)
            if func:
                return func
            else:
                # Try getting external function
                data_addr = getDataAt(func_addr)
                if data_addr:
                    func_name = data_addr.label
                    if func_name:
                        return func_name
                        
                    else:
                        # Look for matching external function
                            ext_ref = data_addr.getExternalReference(0)
                            if ext_ref:
                                ext_fm = currentProgram.getFunctionManager().getExternalFunctions()
                                for f in ext_fm:
                                    if ext_ref.getToAddress().equals(f.getEntryPoint()):
                                        func = f
                                        break
                                return func
        
        # Default return
        return None
        
    def get_condition(self):
        
        nil_string = "{:<36}".format("---")
        condition = None
        
        # Only handle blocks reached by a single condition
        if self.block.getInSize() == 1:
            parent = self.block.getIn(0)
            
            # Check if child is from parent's true or false branch
            branch = None
            if parent.getOutSize() == 2:
                branch = "FALSE" if parent.getFalseOut() == self.block else "TRUE"
            
            parent_ops = [op for op in parent.getIterator()]
            for i in range(len(parent_ops)-1, -1, -1):
                # Find last comparison opcode in parent block (assume it is used in the final jump)
                if parent_ops[i].getMnemonic().endswith(("EQUAL", "LESS", "NEGATE", "AND", "OR")):
                    condition = PCodeOpComparison(parent_ops[i])
                    break
            
            return "If {:<24} is {:<5}".format(condition.to_string(), branch) if condition else nil_string
            
        else:
            return nil_string
     
class IfPCodeBlock(PCodeBlock):
    def __init__(self, pb):
        PCodeBlock.__init__(self, pb)
        assert self.block.getOutSize() == 2, "Block {} has {} outs but IfPCodeBlock must have two outgoing edges.".format(self.address, self.block.getOutSize())
        self.false_out = self.block.getFalseOut()
        self.true_out  = self.block.getTrueOut()
        self.nested_blocks = self.get_nested_blocks()
        
    def wrap_block(self, block):
        # TODO: support wrapping with IfPCodeBlock (currently, get_nested_blocks causes problems)
        if type(block) == PcodeBlockBasic:
            return PCodeBlock(block)
        else:
            return block
    
    def is_in_nested_blocks(self, pb):
        # Checks if PCodeBlock is in nested blocks
        unwrapped_blocks = [b.block for b in self.nested_blocks]
        return pb in unwrapped_blocks
        
    def get_nested_blocks(self):
        # Use sets for O(1) lookups; lists for maintaining order/stack
        stacks = {0: [self.false_out], 1: [self.true_out]}
        visited_lists = {0: [], 1: []}
        visited_sets = {0: set(), 1: set()}

        while stacks[0] or stacks[1]:
            # Iterate through both branches (0 for false, 1 for true)
            for i in [0, 1]:
                if not stacks[i]:
                    continue
                    
                curr = stacks[i].pop()
                other = 1 - i  # The index of the opposite branch

                # Check if branches converged
                if curr in visited_sets[other]:
                    # Trim the opposite branch at the point of convergence
                    idx = visited_lists[other].index(curr)
                    visited_lists[other] = visited_lists[other][:idx]
                    stacks[0], stacks[1] = [], [] # Force break outer loop
                    break

                if curr not in visited_sets[i]:
                    visited_lists[i].append(curr)
                    visited_sets[i].add(curr)
                    # Add successors to the stack
                    stacks[i].extend(curr.getOut(j) for j in range(curr.getOutSize()))

        # Combine results and wrap
        combined = set(visited_lists[0] + visited_lists[1])
        return [self.wrap_block(b) for b in combined]

class FunctionBlocks:
    options = DecompileOptions()
    ifc = DecompInterface()
    ifc.setOptions(options)
    ifc.openProgram(currentProgram)
    monitor = ConsoleTaskMonitor()
    
    def __init__(self, func):
        assert type(func) == FunctionDB, "Input must be function!"
        
        self.func = func
        self.hfunc = self.get_high_function()
        
        self.if_blocks = self.get_if_blocks()
        
    def get_high_function(self):
        res = self.ifc.decompileFunction(self.func, 60, self.monitor)
        return res.getHighFunction()
    
    def get_if_blocks(self):
        blocks = self.hfunc.getBasicBlocks()
        if_blocks = []
        
        for block in blocks:
            if block.getOutSize() == 2:
                
                # Add if-block if it is not already nested in another if-block
                is_nested = False
                for ifb in if_blocks:
                    if ifb.is_in_nested_blocks(block):
                        is_nested = True
                        break
                
                if not is_nested:        
                    if_blocks.append(IfPCodeBlock(block))
        
        return if_blocks
        
def find_dispatchers_if(threshold):
    fm = currentProgram.getFunctionManager()
    funcs = fm.getFunctions(True) # True means 'forward'
    
    for func in funcs:
        # Skip labelled functions 
        if not func.getName().startswith("FUN_"):
            continue
        
        try:
            fb = FunctionBlocks(func)
            for if_block in fb.if_blocks:
                
                # Count how many cases have at least one call
                block_count = len(if_block.nested_blocks)
                blocks_with_calls = 0
                for block in if_block.nested_blocks:
                    if block.calls:
                        blocks_with_calls += 1
                
                if blocks_with_calls >= threshold * block_count and block_count > 4:
                    print("Function {} might contain a dispatcher: Contains if-else block at {} with calls in {}/{} sub-blocks".format(func.getName(), if_block.address, blocks_with_calls, block_count))
                    print("Legend:")
                    print("  <block>  [            <condition>             ]: <calls> (<function names>)")
                    for block in if_block.nested_blocks:
                        separator = ",\n" + " " * 51
                        calls = separator.join(block.calls) if block.calls else ""
                        print("- {} [{}]: {}".format(block.address, block.condition, calls))
                    print("---------------------------------------")
        except:
            print("Failed to analyse function {}".format(func.getName()))
            print("---------------------------------------")
            continue

def main():   
    print("Finding if-else constructs that mostly lead to function calls...\n")
    find_dispatchers_if(0.8)
    
if __name__ == "__main__":
    main()
