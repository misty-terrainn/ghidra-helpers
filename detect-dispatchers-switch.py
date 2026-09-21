from ghidra.program.model.block import BasicBlockModel, CodeBlockImpl
from ghidra.app.decompiler import DecompileOptions, DecompInterface
from ghidra.program.model.listing import Instruction
from ghidra.program.database.code import InstructionDB
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.pcode import JumpTable

import re
from __main__ import *

class Case:
    def __init__(self, bb, value):
        assert type(bb) in [BasicBlockModel, CodeBlockImpl], "Input must be basic block!"
        
        self.bb = bb
        bb_name = bb.getName()
        assert bb_name.startswith("case"), "Input is not a case block!"
        self.name  = bb_name
        self.value = value
        self.calls = self.get_calls()
    
    def get_address(self, a):
        # Convenience function for getting an address from a string or number
        return currentAddress.getAddress(a) if isinstance(a, str) else currentAddress.getNewAddress(a)

    def get_calls(self):
        calls = []
        
        listing = currentProgram.getListing()
        ins_iter = listing.getInstructions(self.bb, True)

        while ins_iter.hasNext():
            instruction = ins_iter.next()
            instruction_address = instruction.getAddressString(False, True)
            
            if instruction.getMnemonicString().startswith("CALL"):
                call_info = "{} {}".format(instruction_address, instruction)
                call_target = self.get_call_target(instruction)
                if call_target: 
                    call_info += " ({})".format(call_target)
                    
                calls.append(call_info)
        
        return calls
  
    def get_call_target(self, call):
        # 1. Type Validation (Guard Clause)
        if not isinstance(call, (Instruction, InstructionDB)):
            return None

        call_target = call.getDefaultOperandRepresentation(0)
        
        # 2. Return early if target is not a hex address (e.g., a register name)
        if not call_target.startswith("0x"):
            return call_target

        # 3. Resolve address
        func_addr = self.get_address(int(call_target, 16))
        
        # 4. Try to find a local function
        func = getFunctionAt(func_addr)
        if func:
            return func

        # 5. Fallback: Check for external functions or labels
        data_addr = getDataAt(func_addr)
        if not data_addr:
            return None

        # Return label if it exists
        if data_addr.label:
            return data_addr.label

        # Search for matching external reference
        ext_ref = data_addr.getExternalReference(0)
        if ext_ref:
            ext_fm = currentProgram.getFunctionManager().getExternalFunctions()
            for f in ext_fm:
                if ext_ref.getToAddress().equals(f.getEntryPoint()):
                    return f

        return None
        
    def get_disassembly(self):
        output_str = ""
        listing = currentProgram.getListing()
        ins_iter = listing.getInstructions(self.bb, True)

        while ins_iter.hasNext():
            ins = ins_iter.next()
            output_str += "{} {}".format(ins.getAddressString(False, True), ins)
            output_str += "\n"
            
        return output_str

class Switch:
    def __init__(self, jt):
        assert type(jt) == JumpTable, "Input must be JumpTable!"
        
        self.jt = jt
        self.address = jt.getSwitchAddress()
        self.cases = []
        
        # Get cases
        caseEAs = jt.getCases() # Contains case block addresses in the same order as label values.
                                # Different labels can have the same case block address.
        labels = jt.getLabelValues()
        self.num_cases = len(caseEAs) 
        
        blockModel = BasicBlockModel(currentProgram)
        monitor = ConsoleTaskMonitor()
        case_blocks = [blockModel.getFirstCodeBlockContaining(caseEA, monitor) for caseEA in caseEAs]
        self.cases += [Case(case_blocks[i], labels[i]) for i in range(len(labels))]
        
        ncaseblocks = len(case_blocks)
        nlabels = len(labels)
        
        # Number of cases can be one more than number of labels, because of the final default case.
        if ncaseblocks != nlabels:
            if ncaseblocks - nlabels == 1:
                self.cases.append(Case(case_blocks[-1], "default"))
            else:
                # Behaviour I haven't encountered
                print("Unhandled: Switch at {} has {} cases, {} labels".format(self.address, ncaseblocks, nlabels))


def get_high_function(func):
    # helper function to convert normal function to HighFunction
    options = DecompileOptions()
    ifc = DecompInterface()
    ifc.setOptions(options)
    ifc.openProgram(getCurrentProgram())
    monitor = ConsoleTaskMonitor()
    res = ifc.decompileFunction(func, 60, monitor)
    return res.getHighFunction()
    
def find_dispatchers_switch(threshold): 
    fm = currentProgram.getFunctionManager()
    funcs = fm.getFunctions(True) # True means 'forward'
    
    for func in funcs: 
        hf = get_high_function(func)
        jts = hf.getJumpTables()
        
        for jt in jts:
            switch = Switch(jt)
            
            # Count how many cases have at least one call
            cases_with_calls = 0
            for case in switch.cases:
                if case.calls:
                    cases_with_calls += 1
            
            if cases_with_calls >= threshold * switch.num_cases:
                print("Function {} might be a dispatcher: Contains switch-case at {} with calls in {}/{} cases".format(func.getName(), switch.address, cases_with_calls, switch.num_cases))
                for case in switch.cases:
                    separator = ",\n" + " " * 12
                    calls = separator.join(case.calls) if case.calls else ""
                    print("- case {:<2} : {}".format(case.value, calls))
                print("---------------------------------------")
    
def main():
    print("Finding switch-case constructs that mostly lead to function calls...\n")
    find_dispatchers_switch(0.8)
    
if __name__ == "__main__":
    main()
