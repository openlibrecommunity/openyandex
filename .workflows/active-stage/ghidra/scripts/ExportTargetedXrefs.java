// Export symbol/function xrefs for target terms.
// Usage:
// analyzeHeadless <project_dir> <project_name> -process <program> -noanalysis \
//   -scriptPath .workflows/active-stage/ghidra/scripts \
//   -postScript ExportTargetedXrefs.java /absolute/out.jsonl term1 term2 ...

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

import java.io.File;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.List;

public class ExportTargetedXrefs extends GhidraScript {
    private static String esc(String value) {
        if (value == null) return "";
        return value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
    }

    private void write(FileWriter out, String schema, String json) throws Exception {
        out.write("{\"schema\":\"" + schema + "\",\"schema_version\":1,\"program\":\"" + esc(currentProgram.getName()) + "\",\"data\":" + json + "}\n");
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            printerr("output path and at least one term required");
            return;
        }
        File outFile = new File(args[0]);
        outFile.getParentFile().mkdirs();
        List<String> terms = new ArrayList<>();
        for (int i = 1; i < args.length; i++) terms.add(args[i].toLowerCase());

        try (FileWriter out = new FileWriter(outFile)) {
            SymbolIterator symbols = currentProgram.getSymbolTable().getSymbolIterator(true);
            int symbolHits = 0;
            while (symbols.hasNext() && symbolHits < 50000 && !monitor.isCancelled()) {
                Symbol s = symbols.next();
                String name = s.getName(true);
                String lower = name.toLowerCase();
                String matched = null;
                for (String term : terms) {
                    if (lower.contains(term)) { matched = term; break; }
                }
                if (matched == null) continue;
                symbolHits++;
                Address addr = s.getAddress();
                write(out, "target_symbol_hit", "{\"term\":\"" + esc(matched) + "\",\"symbol\":\"" + esc(name) + "\",\"address\":\"" + addr.toString() + "\",\"type\":\"" + esc(s.getSymbolType().toString()) + "\"}");
                ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(addr);
                int refCount = 0;
                while (refs.hasNext() && refCount < 200 && !monitor.isCancelled()) {
                    Reference ref = refs.next();
                    Function f = currentProgram.getFunctionManager().getFunctionContaining(ref.getFromAddress());
                    String fn = f == null ? null : f.getName();
                    String entry = f == null ? null : f.getEntryPoint().toString();
                    write(out, "target_xref", "{\"term\":\"" + esc(matched) + "\",\"symbol\":\"" + esc(name) + "\",\"to\":\"" + addr.toString() + "\",\"from\":\"" + ref.getFromAddress().toString() + "\",\"ref_type\":\"" + esc(ref.getReferenceType().toString()) + "\",\"function\":\"" + esc(fn) + "\",\"function_entry\":\"" + esc(entry) + "\"}");
                    refCount++;
                }
            }
        }
        println("wrote " + outFile.getAbsolutePath());
    }
}
