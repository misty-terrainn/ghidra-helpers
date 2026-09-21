# Ghidra Helpers

A small collection of Ghidra scripts for malware reverse engineering: finding behaviour
dispatchers and summarising function calls/references.

## Scripts

### Ghidra Java

- **ListCalleesAndRefs.java** — for every function in the program, lists its immediate callees
  (via `getCalledFunctions`) and x-referenced data (strings/constants). Opens a table-chooser dialog.

### Ghidra Jython (Python)

- **detect-dispatchers-switch.py** — finds *switch-case* constructs where most case blocks lead to
  function calls (a heuristic for command/behaviour dispatchers). Default threshold: 80% of cases.
- **detect-dispatchers-if.py** — finds *nested if-else* constructs where most blocks lead to function
  calls, reconstructing the condition leading into each block.

## Usage

Place scripts in your Ghidra `ghidra_scripts/` directory (or use `-postScript` /
`-preScript` in headless `analyzeHeadless` runs), open a binary, and run from the Script Manager.
The `.py` scripts require the Jython interpreter shipped with Ghidra.

## Notes

- Scripts operate on Ghidra's `currentProgram` / `currentAddress` globals, so they run from the GUI
  or via `analyzeHeadless`.
- Tune the `threshold` value in each `find_dispatchers_*` call to trade recall for precision.
