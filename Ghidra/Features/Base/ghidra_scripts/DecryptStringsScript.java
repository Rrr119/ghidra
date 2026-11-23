/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
// Automatically recover simple statically encrypted strings. Decoder candidates are found by
// inspecting pcode for byte-wise transforms, then the script walks caller levels to collect
// encrypted buffers and key candidates from wrappers and their callers. Recovered strings are
// added as plate comments and Note bookmarks.
//
// Optional script arguments:
//   --max-depth=N         caller levels to inspect (default 4)
//   --max-decoders=N      decoder candidates to inspect (default 24)
//   --min-score=0.68      minimum text-likeness score
//   --max-length=N        maximum encrypted string length (default 512)
//   --dry-run             report results without writing comments or bookmarks
//
//@category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.app.util.decrypt.EncryptedStringRecovery;
import ghidra.app.util.decrypt.EncryptedStringRecovery.Config;
import ghidra.app.util.decrypt.EncryptedStringRecovery.RecoveredString;
import ghidra.app.util.decrypt.EncryptedStringRecovery.RecoveryResult;

public class DecryptStringsScript extends GhidraScript {

	@Override
	public void run() throws Exception {
		if (currentProgram == null) {
			printerr("No active program.");
			return;
		}

		Config config = new Config();
		boolean dryRun = false;
		for (String argument : getScriptArgs()) {
			if ("--dry-run".equals(argument)) {
				dryRun = true;
			}
			else if (argument.startsWith("--max-depth=")) {
				config.maxCallGraphDepth(parseInt(argument, "--max-depth=", 4));
			}
			else if (argument.startsWith("--max-decoders=")) {
				config.maxDecoders(parseInt(argument, "--max-decoders=", 24));
			}
			else if (argument.startsWith("--max-length=")) {
				config.maxStringLength(parseInt(argument, "--max-length=", 512));
			}
			else if (argument.startsWith("--min-score=")) {
				try {
					config.minConfidence(Double.parseDouble(argument.substring(
						"--min-score=".length())));
				}
				catch (NumberFormatException e) {
					printerr("Ignoring invalid --min-score argument: " + argument);
				}
			}
			else if (!argument.isBlank()) {
				printerr("Ignoring unknown argument: " + argument);
			}
		}
		config.annotate(!dryRun);

		println("Scanning " + currentProgram.getName() +
			" for encrypted strings (max caller depth " + config.getMaxCallGraphDepth() +
			")...");
		EncryptedStringRecovery recovery =
			new EncryptedStringRecovery(currentProgram, monitor, config);
		RecoveryResult result = recovery.analyze();

		for (RecoveredString recovered : result.strings()) {
			println(String.format("%s  depth=%d  score=%.2f  [%s]  %s",
				recovered.address(), recovered.callerDepth(), recovered.confidence(),
				recovered.decoder(), recovered.text()));
		}

		double rate = result.getRecoveryRate() * 100.0;
		println(String.format(
			"Recovered %d strings from %d candidate buffers using %d decoder candidates (%.1f%%).",
			result.strings().size(), result.candidateBufferCount(), result.decoderCount(), rate));
		if (dryRun) {
			println("Dry run: no comments or bookmarks were written.");
		}
	}

	private int parseInt(String argument, String prefix, int defaultValue) {
		try {
			return Integer.parseInt(argument.substring(prefix.length()));
		}
		catch (NumberFormatException e) {
			printerr("Ignoring invalid argument: " + argument);
			return defaultValue;
		}
	}
}
