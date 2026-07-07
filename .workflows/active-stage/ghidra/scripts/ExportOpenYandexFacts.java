// Export lightweight facts from the current Ghidra program as JSONL.
// Usage in headless:
// analyzeHeadless <project_dir> <project_name> -process <program> \
//   -scriptPath .workflows/active-stage/ghidra/scripts \
//   -postScript ExportOpenYandexFacts.java /absolute/output.jsonl

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

public class ExportOpenYandexFacts extends GhidraScript {
    private static String esc(String value) {
        if (value == null) return "";
        return value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
    }

    private void write(FileWriter out, String schema, String jsonData) throws IOException {
        Program p = currentProgram;
        out.write("{\"schema\":\"" + schema + "\",\"schema_version\":1,\"program\":\"" + esc(p.getName()) + "\",\"data\":" + jsonData + "}\n");
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
                write(out, "ghidra_function", "{\"name\":\"" + esc(f.getName()) + "\",\"entry\":\"" + f.getEntryPoint().toString() + "\",\"body_size\":" + f.getBody().getNumAddresses() + "}");
            }

            SymbolIterator symbols = currentProgram.getSymbolTable().getSymbolIterator(true);
            int symbolCount = 0;
            while (symbols.hasNext() && symbolCount < 20000 && !monitor.isCancelled()) {
                Symbol s = symbols.next();
                write(out, "ghidra_symbol", "{\"name\":\"" + esc(s.getName(true)) + "\",\"address\":\"" + s.getAddress().toString() + "\",\"type\":\"" + esc(s.getSymbolType().toString()) + "\"}");
                symbolCount++;
            }

        }
        println("wrote " + outFile.getAbsolutePath());
    }
}
