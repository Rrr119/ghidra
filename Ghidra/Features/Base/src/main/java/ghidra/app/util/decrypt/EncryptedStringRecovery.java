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
package ghidra.app.util.decrypt;

import java.util.*;

import ghidra.app.util.decrypt.StringDecryptionEngine.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.util.task.TaskMonitor;

/**
 * Recover simple statically encrypted strings from an analyzed program.
 * <p>
 * The analyzer finds functions whose pcode applies a byte transform to data loaded from
 * memory. It then walks backward through the call graph to collect encrypted buffers and
 * possible keys from wrappers and their callers. Each buffer is decoded with transform
 * candidates inferred from the decoder's pcode and scored before being accepted.
 * <p>
 * This class is intentionally independent from the script wrapper. Other plugins and scripts
 * can construct it with a {@link Program} and {@link TaskMonitor} and consume
 * {@link RecoveryResult} directly.
 */
public class EncryptedStringRecovery {

	/** Default maximum number of caller edges to follow from a decoder. */
	public static final int DEFAULT_MAX_CALL_GRAPH_DEPTH = 4;

	private static final int MAX_INSTRUCTIONS_PER_FUNCTION = 100_000;
	private static final int MAX_KEY_HINTS = 128;
	private static final int MAX_KEY_DATA_LENGTH = 32;

	/**
	 * Analyzer configuration. Defaults are suitable for running the script without prompts.
	 */
	public static class Config {
		private int maxCallGraphDepth = DEFAULT_MAX_CALL_GRAPH_DEPTH;
		private int maxDecoders = 24;
		private int maxStringLength = 512;
		private int maxBuffersPerFunction = 64;
		private double minConfidence = StringDecryptionEngine.DEFAULT_MIN_SCORE;
		private boolean annotate = true;

		public Config maxCallGraphDepth(int depth) {
			this.maxCallGraphDepth = Math.max(0, depth);
			return this;
		}

		public Config maxDecoders(int count) {
			this.maxDecoders = Math.max(1, count);
			return this;
		}

		public Config maxStringLength(int length) {
			this.maxStringLength = Math.max(8, length);
			return this;
		}

		public Config maxBuffersPerFunction(int count) {
			this.maxBuffersPerFunction = Math.max(1, count);
			return this;
		}

		public Config minConfidence(double score) {
			this.minConfidence = Math.max(0.0, Math.min(1.0, score));
			return this;
		}

		public Config annotate(boolean enabled) {
			this.annotate = enabled;
			return this;
		}

		public int getMaxCallGraphDepth() {
			return maxCallGraphDepth;
		}

		public int getMaxDecoders() {
			return maxDecoders;
		}

		public int getMaxStringLength() {
			return maxStringLength;
		}

		public int getMaxBuffersPerFunction() {
			return maxBuffersPerFunction;
		}

		public double getMinConfidence() {
			return minConfidence;
		}

		public boolean isAnnotate() {
			return annotate;
		}
	}

	/**
	 * One recovered string.
	 *
	 * @param address address of the encrypted bytes
	 * @param text recovered text
	 * @param decoder decoder function name
	 * @param confidence text-likeness score
	 * @param callerDepth call graph distance from the decoder to the function containing the
	 *            encrypted bytes
	 */
	public record RecoveredString(Address address, String text, String decoder,
			double confidence, int callerDepth) {
	}

	/**
	 * Result of an analysis run.
	 *
	 * @param strings recovered strings
	 * @param decoderCount number of decoder candidates inspected
	 * @param candidateBufferCount number of unique buffers that were attempted
	 */
	public record RecoveryResult(List<RecoveredString> strings, int decoderCount,
			int candidateBufferCount) {

		public RecoveryResult {
			strings = List.copyOf(strings);
		}

		/**
		 * Fraction of attempted buffers that produced an accepted string. This is a confidence
		 * signal, not a ground-truth sample recovery rate.
		 *
		 * @return recovery ratio from 0 to 1
		 */
		public double getRecoveryRate() {
			return candidateBufferCount == 0 ? 0.0
					: (double) strings.size() / candidateBufferCount;
		}
	}

	private record DecoderCandidate(Function function, List<Operation> operations, int score) {
	}

	private record BufferCandidate(Address address, byte[] bytes, int callerDepth) {
	}

	private record VarnodeKey(String space, long offset, int size) {
	}

	private static class DecoderProfile {
		List<Operation> operations = List.of();
		boolean hasLoad;
		boolean hasStore;
		boolean hasBranch;
		int score;
	}

	private final Program program;
	private final TaskMonitor monitor;
	private final Config config;

	public EncryptedStringRecovery(Program program, TaskMonitor monitor) {
		this(program, monitor, new Config());
	}

	public EncryptedStringRecovery(Program program, TaskMonitor monitor, Config config) {
		this.program = Objects.requireNonNull(program, "program");
		this.monitor = monitor == null ? TaskMonitor.DUMMY : monitor;
		this.config = config == null ? new Config() : config;
	}

	/**
	 * Run the analysis.
	 *
	 * @return recovered strings and summary information
	 */
	public RecoveryResult analyze() {
		List<DecoderCandidate> decoders = findDecoderCandidates();
		if (decoders.isEmpty()) {
			return new RecoveryResult(List.of(), 0, 0);
		}

		Map<Address, RecoveredString> recovered = new LinkedHashMap<>();
		Set<Address> attemptedBuffers = new HashSet<>();
		Set<String> seenKeys = new HashSet<>();

		for (DecoderCandidate decoder : decoders) {
			if (monitor.isCancelled()) {
				break;
			}

			List<CallerLevel<Function>> levels = StringDecryptionEngine.walkCallers(
				decoder.function(), function -> function.getCallingFunctions(monitor),
				config.maxCallGraphDepth);

			List<Key> keys = new ArrayList<>();
			List<BufferCandidate> buffers = new ArrayList<>();
			for (CallerLevel<Function> level : levels) {
				if (monitor.isCancelled()) {
					break;
				}
				collectKeys(level.node(), keys, seenKeys);
				collectBuffers(level.node(), level.depth(), buffers);
			}

			List<Key> limitedKeys = limitKeys(keys);
			List<Transform> transforms =
				StringDecryptionEngine.candidateTransforms(decoder.operations());
			for (BufferCandidate buffer : buffers) {
				if (monitor.isCancelled()) {
					break;
				}
				attemptedBuffers.add(buffer.address());
				Optional<Decoded> decoded = StringDecryptionEngine.decode(buffer.bytes(),
					transforms, limitedKeys, config.maxStringLength, config.minConfidence);
				if (decoded.isEmpty()) {
					continue;
				}
				Decoded result = decoded.get();
				RecoveredString candidate = new RecoveredString(buffer.address(),
					result.text(), decoder.function().getName(), result.score(),
					buffer.callerDepth());
				RecoveredString existing = recovered.get(buffer.address());
				if (existing == null || candidate.confidence() > existing.confidence()) {
					recovered.put(buffer.address(), candidate);
				}
			}
		}

		List<RecoveredString> strings = new ArrayList<>(recovered.values());
		strings.sort(Comparator.comparing(RecoveredString::address));
		if (config.annotate) {
			annotate(strings);
		}
		return new RecoveryResult(strings, decoders.size(), attemptedBuffers.size());
	}

	private List<DecoderCandidate> findDecoderCandidates() {
		List<DecoderCandidate> candidates = new ArrayList<>();
		FunctionManager functionManager = program.getFunctionManager();
		FunctionIterator functions = functionManager.getFunctions(true);
		while (functions.hasNext() && !monitor.isCancelled()) {
			Function function = functions.next();
			if (function.isExternal() || function.isThunk()) {
				continue;
			}
			DecoderProfile profile = profile(function);
			if (profile.score >= 4) {
				candidates.add(
					new DecoderCandidate(function, profile.operations, profile.score));
			}
		}

		candidates.sort(Comparator.comparingInt(DecoderCandidate::score)
				.reversed()
				.thenComparing(candidate -> candidate.function().getEntryPoint()));
		if (candidates.size() > config.maxDecoders) {
			return List.copyOf(candidates.subList(0, config.maxDecoders));
		}
		return List.copyOf(candidates);
	}

	private DecoderProfile profile(Function function) {
		DecoderProfile profile = new DecoderProfile();
		LinkedHashSet<Operation> operations = new LinkedHashSet<>();
		Set<VarnodeKey> tainted = new HashSet<>();
		boolean sawLeft = false;
		boolean sawRight = false;
		int instructions = 0;

		InstructionIterator iterator =
			program.getListing().getInstructions(function.getBody(), true);
		while (iterator.hasNext() && !monitor.isCancelled()) {
			Instruction instruction = iterator.next();
			if (++instructions > MAX_INSTRUCTIONS_PER_FUNCTION) {
				break;
			}
			for (PcodeOp op : instruction.getPcode()) {
				int opcode = op.getOpcode();
				Varnode[] inputs = op.getInputs();

				if (opcode == PcodeOp.LOAD) {
					profile.hasLoad = true;
					Varnode output = op.getOutput();
					if (output != null && output.getSize() <= 4) {
						tainted.add(varnodeKey(output));
					}
					continue;
				}
				if (opcode == PcodeOp.STORE) {
					if (inputs.length > 2 && isTainted(inputs[2], tainted)) {
						profile.hasStore = true;
					}
					continue;
				}
				if (opcode == PcodeOp.BRANCH || opcode == PcodeOp.CBRANCH) {
					profile.hasBranch = true;
					continue;
				}

				boolean taintedInput = anyTainted(inputs, tainted);
				if (!taintedInput) {
					continue;
				}

				switch (opcode) {
					case PcodeOp.INT_XOR -> operations.add(Operation.XOR);
					case PcodeOp.INT_ADD -> operations.add(Operation.ADD);
					case PcodeOp.INT_SUB -> operations.add(Operation.SUB);
					case PcodeOp.INT_LEFT -> sawLeft = true;
					case PcodeOp.INT_RIGHT, PcodeOp.INT_SRIGHT -> sawRight = true;
					default -> {
						// Several other pcode operations can appear in a decoder's data path
						// (zero-extension, masks, copies, multiplies). They keep the value
						// tainted, but do not identify the byte transform by themselves.
					}
				}

				Varnode output = op.getOutput();
				if (output != null && output.getSize() <= 8) {
					tainted.add(varnodeKey(output));
				}
			}
		}

		if (sawLeft && sawRight) {
			operations.add(Operation.ROL);
			operations.add(Operation.ROR);
		}

		profile.operations = List.copyOf(operations);
		String name = function.getName().toLowerCase(Locale.ROOT);
		boolean nameHint = name.contains("decrypt") || name.contains("decode") ||
			name.contains("deobfus") || name.contains("xor") || name.contains("crypt");

		profile.score = operations.size() * 2 +
			(profile.hasLoad ? 1 : 0) +
			(profile.hasStore ? 2 : 0) +
			(profile.hasBranch ? 1 : 0) +
			(nameHint ? 4 : 0);
		if (!profile.hasLoad) {
			profile.score = 0;
		}
		return profile;
	}

	private void collectKeys(Function function, List<Key> keys, Set<String> seenKeys) {
		LinkedHashSet<Address> seenAddresses = new LinkedHashSet<>();
		List<Long> deferredConstants = new ArrayList<>();
		InstructionIterator iterator =
			program.getListing().getInstructions(function.getBody(), true);
		while (iterator.hasNext() && !monitor.isCancelled() && keys.size() < MAX_KEY_HINTS) {
			Instruction instruction = iterator.next();
			collectDataReferenceKeys(instruction, keys, seenKeys, seenAddresses);
		}

		iterator = program.getListing().getInstructions(function.getBody(), true);
		while (iterator.hasNext() && !monitor.isCancelled() && keys.size() < MAX_KEY_HINTS) {
			Instruction instruction = iterator.next();
			for (PcodeOp op : instruction.getPcode()) {
				for (Varnode input : op.getInputs()) {
					if (input.isConstant()) {
						long value = input.getOffset();
						if (value > 0 && value <= 0xffffL) {
							addConstantKeys(value, keys, seenKeys);
						}
						else if (value > 0xffffL && value <= 0xffffffffL &&
							deferredConstants.size() < MAX_KEY_HINTS) {
							deferredConstants.add(value);
						}
					}
				}
				if (keys.size() >= MAX_KEY_HINTS) {
					break;
				}
			}
		}
		for (long value : deferredConstants) {
			if (keys.size() >= MAX_KEY_HINTS) {
				break;
			}
			addConstantKeys(value, keys, seenKeys);
		}
	}

	private void collectDataReferenceKeys(Instruction instruction, List<Key> keys,
			Set<String> seenKeys, Set<Address> seenAddresses) {
		Reference[] references =
			program.getReferenceManager().getReferencesFrom(instruction.getAddress());
		for (Reference reference : references) {
			if (keys.size() >= MAX_KEY_HINTS) {
				return;
			}
			Address target = reference.getToAddress();
			if (target == null || !seenAddresses.add(target)) {
				continue;
			}
			byte[] bytes = readCString(target, MAX_KEY_DATA_LENGTH);
			if (bytes.length == 0) {
				continue;
			}
			addKey(bytes, "data@" + target, keys, seenKeys);
		}
	}

	private void addConstantKeys(long value, List<Key> keys, Set<String> seenKeys) {
		if (value == 0 || value > 0xffffffffL || keys.size() >= MAX_KEY_HINTS) {
			return;
		}
		addKey(new byte[] { (byte) value }, "constant", keys, seenKeys);
		if (value <= 0xffffL) {
			addKey(new byte[] { (byte) value, (byte) (value >>> 8) }, "constant-le",
				keys, seenKeys);
			addKey(new byte[] { (byte) (value >>> 8), (byte) value }, "constant-be",
				keys, seenKeys);
		}
		if (value > 0xffffL) {
			addKey(new byte[] { (byte) value, (byte) (value >>> 8),
				(byte) (value >>> 16), (byte) (value >>> 24) }, "constant-le", keys,
				seenKeys);
			addKey(new byte[] { (byte) (value >>> 24), (byte) (value >>> 16),
				(byte) (value >>> 8), (byte) value }, "constant-be", keys, seenKeys);
		}
	}

	private void addKey(byte[] bytes, String description, List<Key> keys,
			Set<String> seenKeys) {
		if (bytes.length == 0 || keys.size() >= MAX_KEY_HINTS) {
			return;
		}
		String id = Base64.getEncoder().encodeToString(bytes);
		if (seenKeys.add(id)) {
			keys.add(new Key(bytes, description));
		}
	}

	private void collectBuffers(Function function, int depth, List<BufferCandidate> buffers) {
		if (buffers.size() >= config.maxBuffersPerFunction) {
			return;
		}
		LinkedHashSet<Address> seen = new LinkedHashSet<>();
		for (BufferCandidate buffer : buffers) {
			seen.add(buffer.address());
		}

		InstructionIterator iterator =
			program.getListing().getInstructions(function.getBody(), true);
		while (iterator.hasNext() && !monitor.isCancelled() &&
			buffers.size() < config.maxBuffersPerFunction) {
			Instruction instruction = iterator.next();
			Reference[] references =
				program.getReferenceManager().getReferencesFrom(instruction.getAddress());
			for (Reference reference : references) {
				addBuffer(reference.getToAddress(), depth, buffers, seen);
				if (buffers.size() >= config.maxBuffersPerFunction) {
					return;
				}
			}
		}

		iterator = program.getListing().getInstructions(function.getBody(), true);
		while (iterator.hasNext() && !monitor.isCancelled() &&
			buffers.size() < config.maxBuffersPerFunction) {
			Instruction instruction = iterator.next();
			for (PcodeOp op : instruction.getPcode()) {
				for (Varnode input : op.getInputs()) {
					if (!input.isConstant()) {
						continue;
					}
					addBuffer(constantAddress(input.getOffset()), depth, buffers, seen);
					if (buffers.size() >= config.maxBuffersPerFunction) {
						return;
					}
				}
			}
		}
	}

	private void addBuffer(Address address, int depth, List<BufferCandidate> buffers,
			Set<Address> seen) {
		if (address == null || !seen.add(address) || !program.getMemory().contains(address)) {
			return;
		}
		byte[] bytes = readBytes(address, config.maxStringLength);
		if (bytes.length >= 4 && !allZero(bytes)) {
			buffers.add(new BufferCandidate(address, bytes, depth));
			addNulTerminatedPrefix(address, bytes, depth, buffers);
		}

		int pointerSize = program.getDefaultPointerSize();
		if (bytes.length >= pointerSize && pointerSize >= 2) {
			try {
				long value = program.getMemory().getLong(address,
					program.getLanguage().isBigEndian());
				Address pointedAddress = constantAddress(value);
				if (pointedAddress != null && !pointedAddress.equals(address) &&
					seen.add(pointedAddress) && program.getMemory().contains(pointedAddress)) {
					byte[] pointedBytes =
						readBytes(pointedAddress, config.maxStringLength);
					if (pointedBytes.length >= 4 && !allZero(pointedBytes)) {
						buffers.add(new BufferCandidate(pointedAddress, pointedBytes, depth));
						addNulTerminatedPrefix(pointedAddress, pointedBytes, depth, buffers);
					}
				}
			}
			catch (MemoryAccessException e) {
				// Not a readable pointer. The direct buffer was already considered.
			}
		}
	}

	private static void addNulTerminatedPrefix(Address address, byte[] bytes, int depth,
			List<BufferCandidate> buffers) {
		for (int i = 0; i < bytes.length; i++) {
			if (bytes[i] == 0) {
				if (i >= 4) {
					buffers.add(new BufferCandidate(address, Arrays.copyOf(bytes, i), depth));
				}
				return;
			}
		}
	}

	private Address constantAddress(long value) {
		if (value <= 0) {
			return null;
		}
		try {
			AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
			return space.getAddress(value);
		}
		catch (RuntimeException e) {
			return null;
		}
	}

	private byte[] readBytes(Address address, int maxLength) {
		if (address == null || !program.getMemory().contains(address)) {
			return new byte[0];
		}
		byte[] bytes = new byte[maxLength];
		int length = 0;
		Address current = address;
		try {
			while (length < maxLength && program.getMemory().contains(current)) {
				byte value = program.getMemory().getByte(current);
				bytes[length++] = value;
				current = current.add(1);
			}
		}
		catch (MemoryAccessException | RuntimeException e) {
			if (length == 0) {
				return new byte[0];
			}
		}
		return Arrays.copyOf(bytes, length);
	}

	private byte[] readCString(Address address, int maxLength) {
		byte[] bytes = readBytes(address, maxLength);
		for (int i = 0; i < bytes.length; i++) {
			if (bytes[i] == 0) {
				return Arrays.copyOf(bytes, i);
			}
		}
		return bytes;
	}

	private void annotate(List<RecoveredString> strings) {
		BookmarkManager bookmarkManager = program.getBookmarkManager();
		Listing listing = program.getListing();
		for (RecoveredString recovered : strings) {
			String escaped = recovered.text().replace("\\", "\\\\").replace("\"", "\\\"");
			String comment = "Recovered string [" + recovered.decoder() + "]: \"" + escaped +
				"\"";
			String existing = listing.getComment(CommentType.PLATE, recovered.address());
			if (existing == null || existing.isBlank()) {
				listing.setComment(recovered.address(), CommentType.PLATE, comment);
			}
			else if (!existing.contains(comment)) {
				listing.setComment(recovered.address(), CommentType.PLATE,
					existing + "\n" + comment);
			}
			bookmarkManager.setBookmark(recovered.address(), BookmarkType.NOTE,
				"DecryptStringsScript", recovered.text());
		}
	}

	private static List<Key> limitKeys(List<Key> keys) {
		if (keys.size() <= MAX_KEY_HINTS) {
			return List.copyOf(keys);
		}
		return List.copyOf(keys.subList(0, MAX_KEY_HINTS));
	}

	private static boolean anyTainted(Varnode[] inputs, Set<VarnodeKey> tainted) {
		for (Varnode input : inputs) {
			if (isTainted(input, tainted)) {
				return true;
			}
		}
		return false;
	}

	private static boolean isTainted(Varnode varnode, Set<VarnodeKey> tainted) {
		return varnode != null && tainted.contains(varnodeKey(varnode));
	}

	private static VarnodeKey varnodeKey(Varnode varnode) {
		Address address = varnode.getAddress();
		String space = address == null || address.getAddressSpace() == null ? ""
				: address.getAddressSpace().getName();
		long offset = address == null ? varnode.getOffset() : address.getOffset();
		return new VarnodeKey(space, offset, varnode.getSize());
	}

	private static boolean allZero(byte[] bytes) {
		for (byte value : bytes) {
			if (value != 0) {
				return false;
			}
		}
		return true;
	}
}
