# -*- coding: utf-8 -*-
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

# Output file path
OUTPUT_FILE = "C:\\Users\\username\\Downloads\\decompiled_functions.txt"  # Replace 'username' with your Windows username

def main():
    # Prompt user for start and end addresses
    START_ADDR = int(askLong("Start Address", "Enter the start address for decompilation (hexadecimal):"))
    END_ADDR = int(askLong("End Address", "Enter the end address for decompilation (hexadecimal):"))
    CLASS_NAME = askString("Class Name", "Enter the class name to filter functions (exact match):")
    
    # Initialize decompiler
    decompiler = DecompInterface()
    decompiler.openProgram(currentProgram)
    
    # Initialize monitor
    monitor = ConsoleTaskMonitor()
    
    # Write output to file
    with open(OUTPUT_FILE, "w") as f:
        f.write("Decompilation started for class: {}...\n".format(CLASS_NAME))
        fm = currentProgram.getFunctionManager()
        functions = fm.getFunctions(True)

        for func in functions:
            entry_point = func.getEntryPoint().getOffset()
            
            # Get the parent namespace (class name)
            namespace = func.getParentNamespace()
            namespace_name = namespace.getName() if namespace else ""
            func_name = func.getName()

            # Check if the function belongs to the specified class
            # Include constructors explicitly by checking func_name == CLASS_NAME
            is_class_match = (namespace_name == CLASS_NAME or func_name == CLASS_NAME)

            # Check if function is within address range and matches class
            if (START_ADDR <= entry_point <= END_ADDR and is_class_match):
                func_addr = hex(entry_point)
                # Construct the full name for display (e.g., Item::setUseAnimation)
                full_name = "{}::{}".format(namespace_name, func_name) if namespace_name else func_name
                if func_name == CLASS_NAME:  # For constructor, adjust the display name
                    full_name = "{}::{}".format(CLASS_NAME, CLASS_NAME)
                print("Decompiling: {} @ {}".format(full_name, func_addr))
                f.write("\n" + "="*50 + "\n")
                f.write("Function: {} @ {}\n".format(full_name, func_addr))
                f.write("="*50 + "\n")

                decomp_result = decompiler.decompileFunction(func, 0, monitor)
                if decomp_result and decomp_result.decompileCompleted():
                    decompiled_code = decomp_result.getDecompiledFunction().getC()
                    f.write(decompiled_code + "\n")
                else:
                    f.write("Failed to decompile function.\n")

    print("Decompilation complete. Output written to: {}".format(OUTPUT_FILE))

if __name__ == "__main__":
    main()
