// Export function-level facts for custom Ghidra+rizin diffing.
// Usage:
// analyzeHeadless <project_dir> <project_name> -process <program> -noanalysis \
//   -scriptPath .workflows/active-stage/ghidra/scripts \
//   -postScript ExportOpenYandexFunctionDiffFacts.java /absolute/output.jsonl

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;

import java.io.File;
import java.io.FileWriter;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;

public class ExportOpenYandexFunctionDiffFacts extends GhidraScript {
    private static String esc(String value) {
        if (value == null) return "";
        return value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
    }

    private static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b & 0xff));
        return sb.toString();
    }

    private String sha256(String value) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return hex(md.digest(value.getBytes("UTF-8")));
    }

    private void write(FileWriter out, String jsonData) throws Exception {
        out.write("{\"schema\":\"ghidra_function_diff_fact\",\"schema_version\":1,\"program\":\"" + esc(currentProgram.getName()) + "\",\"data\":" + jsonData + "}\n");
    }

    private String jsonArray(Iterable<String> values) {
        StringBuilder sb = new StringBuilder("[");
        boolean first = true;
        for (String value : values) {
            if (!first) sb.append(',');
            sb.append("\"").append(esc(value)).append("\"");
            first = false;
        }
        sb.append(']');
        return sb.toString();
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("output JSONL path required");
            return;
        }
        File outFile = new File(args[0]);
        outFile.getParentFile().mkdirs();

        try (FileWriter out = new FileWriter(outFile)) {
            FunctionIterator funcs = currentProgram.getFunctionManager().getFunctions(true);
            while (funcs.hasNext() && !monitor.isCancelled()) {
                Function f = funcs.next();
                StringBuilder mnemonicStream = new StringBuilder();
                int instructionCount = 0;
                LinkedHashSet<String> called = new LinkedHashSet<>();
                LinkedHashSet<String> externalRefs = new LinkedHashSet<>();
                LinkedHashSet<String> stringRefs = new LinkedHashSet<>();

                InstructionIterator it = currentProgram.getListing().getInstructions(f.getBody(), true);
                while (it.hasNext() && !monitor.isCancelled()) {
                    Instruction ins = it.next();
                    instructionCount++;
                    mnemonicStream.append(ins.getMnemonicString()).append(' ');
                    Reference[] refs = ins.getReferencesFrom();
                    for (Reference ref : refs) {
                        Address to = ref.getToAddress();
                        if (to == null) continue;
                        Symbol s = currentProgram.getSymbolTable().getPrimarySymbol(to);
                        if (s != null) {
                            String name = s.getName(true);
                            if (s.isExternal()) externalRefs.add(name);
                            if (ref.getReferenceType().isCall()) called.add(name);
                        }
                        CodeUnit cu = currentProgram.getListing().getCodeUnitAt(to);
                        if (cu instanceof Data && ((Data) cu).getDataType() != null) {
                            String dt = ((Data) cu).getDataType().getName().toLowerCase();
                            if (dt.contains("string") || dt.contains("unicode")) {
                                stringRefs.add(cu.toString());
                            }
                        }
                    }
                }

                String json = "{"
                    + "\"name\":\"" + esc(f.getName()) + "\"," 
                    + "\"entry\":\"" + f.getEntryPoint().toString() + "\"," 
                    + "\"body_size\":" + f.getBody().getNumAddresses() + ","
                    + "\"instruction_count\":" + instructionCount + ","
                    + "\"mnemonic_hash\":\"" + sha256(mnemonicStream.toString()) + "\"," 
                    + "\"called_symbols\":" + jsonArray(called) + ","
                    + "\"external_refs\":" + jsonArray(externalRefs) + ","
                    + "\"string_refs\":" + jsonArray(stringRefs)
                    + "}";
                write(out, json);
            }
        }
        println("wrote " + outFile.getAbsolutePath());
    }
}
