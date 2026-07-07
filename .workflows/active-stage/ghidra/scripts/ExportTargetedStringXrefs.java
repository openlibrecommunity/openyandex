// Export xrefs to defined string data containing target terms.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

import java.io.File;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.List;

public class ExportTargetedStringXrefs extends GhidraScript {
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
            ghidra.program.model.listing.DataIterator it = currentProgram.getListing().getDefinedData(true);
            int hits = 0;
            while (it.hasNext() && hits < 20000 && !monitor.isCancelled()) {
                Data data = it.next();
                Object value = data.getValue();
                if (value == null) continue;
                String text = value.toString();
                String lower = text.toLowerCase();
                String matched = null;
                for (String term : terms) {
                    if (lower.contains(term)) { matched = term; break; }
                }
                if (matched == null) continue;
                hits++;
                Address addr = data.getAddress();
                write(out, "target_string_hit", "{\"term\":\"" + esc(matched) + "\",\"address\":\"" + addr.toString() + "\",\"value\":\"" + esc(text) + "\"}");
                ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(addr);
                int count = 0;
                while (refs.hasNext() && count < 200 && !monitor.isCancelled()) {
                    Reference ref = refs.next();
                    Function f = currentProgram.getFunctionManager().getFunctionContaining(ref.getFromAddress());
                    write(out, "target_string_xref", "{\"term\":\"" + esc(matched) + "\",\"string_address\":\"" + addr.toString() + "\",\"value\":\"" + esc(text) + "\",\"from\":\"" + ref.getFromAddress().toString() + "\",\"ref_type\":\"" + esc(ref.getReferenceType().toString()) + "\",\"function\":\"" + esc(f == null ? null : f.getName()) + "\",\"function_entry\":\"" + esc(f == null ? null : f.getEntryPoint().toString()) + "\"}");
                    count++;
                }
            }
        }
        println("wrote " + outFile.getAbsolutePath());
    }
}
