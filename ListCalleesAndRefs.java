//Script to list immediate callees of all functions
//@author misty-terrain
//@category Functions
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.script.GhidraScript;
import ghidra.app.tablechooser.AbstractComparableColumnDisplay;
import ghidra.app.tablechooser.AddressableRowObject;
import ghidra.app.tablechooser.ColumnDisplay;
import ghidra.app.tablechooser.StringColumnDisplay;
import ghidra.app.tablechooser.TableChooserDialog;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.RefType;
import ghidra.program.util.CyclomaticComplexity;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import java.util.Set;

// based off of ComputeCyclomaticComplexity.java
// CompareFunctionSizesScript.java provides a useful example for writing plugins with UI popups

/*
	./analyzeHeadless [path to directory containing .g] [project name] -process -prescript [path to this script] -noanalysis
	$ ./analyzeHeadless ~/research/INFILTRATE/projects/ test.gpr -process -prescript ~/ghidra_scripts/CompletedListCalleesAndReferences.java -noanalysis
*/

public class ListCalleesAndReferences extends GhidraScript {

	private CyclomaticComplexity cyclo = new CyclomaticComplexity();

	@Override
	protected void run() throws Exception {
		if (currentProgram == null) {
			printerr("no current program");
			return;
		}
		
		FunctionIterator functionIterator = currentProgram.getFunctionManager().getFunctions(true);
		
		if (!isRunningHeadless()) {
			TableChooserDialog tableDialog = createTableChooserDialog(currentProgram.getName() + " - Function Callees", null, false);
			configureTableColumns(tableDialog);
			
			tableDialog.show();
						
			for ( Function currentFunction : functionIterator ) {
				FunctionFeatures callees = new FunctionFeatures(currentFunction); 
				tableDialog.add(callees);
			}
			
		}
		else { //isRunningHeadless
			printerr("headless mode not implemented");
            return;
		}
	}
	
	private class FunctionFeatures implements AddressableRowObject {

		private Function function;
		//private Integer functionCyclomaticComplexity;
		private Address functionAddress;
        private Set<Function> called;
        private String strings;
		
		public FunctionFeatures(Function f) throws CancelledException {
			function = f;
			
            // Get called functions (internally, a reference is treated as a call)
			functionAddress = function.getEntryPoint();
            called = f.getCalledFunctions(TaskMonitor.DUMMY);
            
            // Get x-referenced data
            strings = "";
            ReferenceManager referenceManager = currentProgram.getReferenceManager();
            Address maxAddr = function.getBody().getMaxAddress();
            
            Instruction instr = getInstructionAt(functionAddress);
            Reference[] referenceList;
            while (instr != null && instr.getMinAddress().compareTo(maxAddr) < 0){
                referenceList = referenceManager.getReferencesFrom(instr.getMinAddress());
                
                for (Reference r : referenceList) {
                    if (r.getReferenceType() == RefType.DATA) {
                        Data data = getDataAt(r.getToAddress());
                        if (data != null) {
                            if (strings.isEmpty())
                                strings = data.getDefaultValueRepresentation();
                            else
                                strings = strings + ", " + data.getDefaultValueRepresentation();                        
                        }
                    }
                }
                
                instr = getInstructionAfter(instr);
            }
            
        }
		
		@Override
		public Address getAddress() {
			return functionAddress;
		} 
		
		public Function getFunction() {
			return function;
		}
		
		public Set getCallees() {
			return called;
		}
        
        public String getStrings(){
            return strings;
        }
		
	}
	
    
	private void configureTableColumns(TableChooserDialog dialog) throws CancelledException {
		
		StringColumnDisplay functionNameColumn = new StringColumnDisplay() {
			
			@Override
			public String getColumnName() {
				return "Function Name";
			}

			@Override
			public String getColumnValue(AddressableRowObject rowObject) {
				return ((FunctionFeatures) rowObject).getFunction().getName();
			}
		};
		
		ColumnDisplay<String> calleesColumn = new AbstractComparableColumnDisplay<String>() {

			@Override
			public String getColumnValue(AddressableRowObject rowObject) {
				String calleeList = ((FunctionFeatures) rowObject).getCallees().toString();
                String calleesWithNewlines = calleeList.replace(", ",", \n");
                return calleesWithNewlines;
			}

			@Override
			public String getColumnName() {
				return "Callees";
			}
			
		};
		
        ColumnDisplay<String> dataColumn = new AbstractComparableColumnDisplay<String>() {
			
			@Override
			public String getColumnName() {
				return "X-referenced Data";
			}

			@Override
			public String getColumnValue(AddressableRowObject rowObject) {
				return ((FunctionFeatures) rowObject).getStrings();
			}
		};
        
        
		dialog.addCustomColumn(functionNameColumn);
		dialog.addCustomColumn(calleesColumn);
        dialog.addCustomColumn(dataColumn);
	}
    
    
}
