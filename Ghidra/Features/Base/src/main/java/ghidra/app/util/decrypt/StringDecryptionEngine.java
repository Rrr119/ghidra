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

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Architecture-independent helpers for recovering statically encrypted strings.
 * <p>
 * The Ghidra script uses this engine after it has collected encrypted buffers and key
 * candidates from a function's call graph. Keeping the transform and text-scoring logic here
 * makes the heuristics reusable and testable without an open program.
 */
public final class StringDecryptionEngine {

	/** Default minimum confidence for accepting a recovered string. */
	public static final double DEFAULT_MIN_SCORE = 0.68;

	private static final int MIN_STRING_LENGTH = 4;
	private static final int MAX_TRANSFORM_STEPS = 6;
	private static final int MAX_EXPANDED_TRANSFORMS = 128;

	private static final Set<String> COMMON_BIGRAMS = Set.of(
		"th", "he", "in", "er", "an", "re", "on", "at", "en", "nd", "ti", "es", "or",
		"te", "of", "ed", "is", "it", "al", "ar", "st", "to", "nt", "ng", "se", "ha",
		"as", "ou", "io", "le", "ve", "co", "me", "de", "hi", "ri", "ro", "ic", "ne",
		"ea", "ra", "ce", "li", "ch", "ll", "be", "ma", "si", "om", "ur", "ca", "el",
		"la", "ns", "di", "fo", "ho", "pe", "ec", "pr", "no", "ct", "us", "ac", "il",
		"tr", "ly", "un", "wi", "ge", "lo", "ss", "so", "rs", "rt", "ut", "we");

	private static final Set<String> COMMON_TRIGRAMS = Set.of(
		"the", "and", "ing", "her", "hat", "his", "tha", "ere", "for", "ent", "ion",
		"ter", "was", "you", "ith", "ver", "all", "wit", "thi", "tio", "nde", "has",
		"men", "not", "are", "but", "from", "they", "this", "that", "with", "have",
		"str", "cti", "ons", "res", "con", "com", "www", "htt", "tps", "dll", "exe",
		"key", "sub");

	private static final Set<String> COMMON_WORDS = Set.of(
		"the", "and", "for", "you", "are", "but", "not", "with", "this", "that",
		"from", "have", "was", "were", "will", "can", "could", "should", "would",
		"error", "failed", "success", "hello", "world", "test", "sample", "build",
		"complete", "recovered", "string", "strings", "encrypt", "decrypt", "debug",
		"file", "path", "user", "admin", "root", "password", "secret", "token",
		"key", "flag", "data", "buffer", "memory", "process", "module", "library",
		"windows", "system", "kernel", "network", "socket", "connect", "open",
		"close", "read", "write", "create", "delete", "load", "save", "start", "stop",
		"multi", "sub", "xor", "rotate", "reverse", "registry", "output", "example",
		"text", "dll", "http", "com", "createfile", "then", "add", "me");

	private static final Set<String> COMMON_TOKENS = Set.of(
		"http", "https", "www", ".com", ".net", ".org", ".dll", ".exe", ".sys",
		".bin", ".dat", ".txt", ".log", ".json", ".xml", "cmd", "powershell",
		"password", "secret", "token", "kernel", "user32", "advapi", "ws2_32",
		"createfile", "virtualalloc", "winexec", "shellexecute", "error", "failed",
		"success", "hello", "world", "test", "sample", "build", "complete",
		"recovered", "decrypt", "encrypt", "debug", "system", "windows");

	private StringDecryptionEngine() {
		// utility class
	}

	/**
	 * Supported per-byte transform operations.
	 */
	public enum Operation {
		XOR, ADD, SUB, ROL, ROR, NOT, REVERSE
	}

	/**
	 * A byte key candidate with a human-readable provenance.
	 *
	 * @param bytes key bytes
	 * @param description where the key came from, for reporting
	 */
	public record Key(byte[] bytes, String description) {
		public Key {
			bytes = bytes == null ? new byte[0] : bytes.clone();
			description = description == null ? "" : description;
		}

		@Override
		public byte[] bytes() {
			return bytes.clone();
		}
	}

	/**
	 * One operation in a transform pipeline.
	 *
	 * @param operation operation kind
	 * @param amount rotation amount, ignored by non-rotation operations
	 */
	public record Step(Operation operation, int amount) {
		public Step {
			Objects.requireNonNull(operation, "operation");
		}
	}

	/**
	 * An ordered sequence of operations applied to encrypted bytes.
	 *
	 * @param steps transform steps
	 * @param label display label
	 */
	public record Transform(List<Step> steps, String label) {
		public Transform {
			steps = List.copyOf(steps);
			if (steps.isEmpty()) {
				throw new IllegalArgumentException("A transform needs at least one step");
			}
			label = label == null ? "" : label;
		}

		boolean usesKey() {
			for (Step step : steps) {
				if (step.operation() == Operation.XOR || step.operation() == Operation.ADD ||
					step.operation() == Operation.SUB) {
					return true;
				}
			}
			return false;
		}
	}

	/**
	 * A successful decode result.
	 *
	 * @param plaintext decoded bytes, truncated at the first NUL
	 * @param text decoded text
	 * @param transform transform that produced the text
	 * @param key key that produced the text, or {@code null} for keyless transforms
	 * @param score text-likeness score in the range 0 to 1
	 */
	public record Decoded(byte[] plaintext, String text, Transform transform, Key key,
			double score) {
		public Decoded {
			plaintext = plaintext.clone();
		}

		@Override
		public byte[] plaintext() {
			return plaintext.clone();
		}
	}

	/**
	 * One caller level produced while walking a call graph.
	 *
	 * @param <T> node type
	 * @param node node at this level
	 * @param depth zero for the starting node
	 */
	public record CallerLevel<T>(T node, int depth) {
	}

	/**
	 * Supplies callers for a node.
	 *
	 * @param <T> node type
	 */
	@FunctionalInterface
	public interface CallerProvider<T> {
		Collection<T> callersOf(T node);
	}

	/**
	 * Walk callers breadth-first, starting at {@code root}. This is deliberately independent
	 * of Ghidra so that call-graph propagation can be tested directly.
	 *
	 * @param <T> node type
	 * @param root starting node, usually the decoder
	 * @param provider caller provider
	 * @param maxDepth maximum number of caller edges to follow
	 * @return unique nodes in breadth-first order, root first
	 */
	public static <T> List<CallerLevel<T>> walkCallers(T root, CallerProvider<T> provider,
			int maxDepth) {
		if (root == null || maxDepth < 0) {
			return List.of();
		}

		List<CallerLevel<T>> result = new ArrayList<>();
		Set<T> visited = new LinkedHashSet<>();
		Deque<CallerLevel<T>> queue = new ArrayDeque<>();
		queue.add(new CallerLevel<>(root, 0));

		while (!queue.isEmpty()) {
			CallerLevel<T> current = queue.removeFirst();
			if (!visited.add(current.node())) {
				continue;
			}
			result.add(current);
			if (current.depth() >= maxDepth) {
				continue;
			}

			Collection<T> callers = provider.callersOf(current.node());
			if (callers == null) {
				continue;
			}
			for (T caller : callers) {
				if (caller != null && !visited.contains(caller)) {
					queue.addLast(new CallerLevel<>(caller, current.depth() + 1));
				}
			}
		}
		return Collections.unmodifiableList(result);
	}

	/**
	 * Generate transform candidates from operations observed in a decoder. Both the exact
	 * observed sequence and individual operations are tried, because pcode commonly contains
	 * address arithmetic in addition to the actual string transform.
	 *
	 * @param observedOperations ordered operations observed in the decoder
	 * @return deduplicated candidate transforms, most specific first
	 */
	public static List<Transform> candidateTransforms(List<Operation> observedOperations) {
		List<Operation> observed = normalizeOperations(observedOperations);
		LinkedHashMap<String, Transform> transforms = new LinkedHashMap<>();

		if (!observed.isEmpty() && observed.size() <= MAX_TRANSFORM_STEPS) {
			addExpandedSequence(transforms, observed);
		}

		for (Operation operation : observed) {
			addIndividualTransforms(transforms, operation);
		}

		if (observed.size() > 1) {
			List<Operation> pairs = new ArrayList<>(observed);
			for (int i = 0; i < pairs.size(); i++) {
				for (int j = 0; j < pairs.size(); j++) {
					if (i != j) {
						addExpandedSequence(transforms, List.of(pairs.get(i), pairs.get(j)));
					}
				}
			}
		}

		if (transforms.isEmpty()) {
			for (Operation operation : Operation.values()) {
				addIndividualTransforms(transforms, operation);
			}
		}

		return List.copyOf(transforms.values());
	}

	/**
	 * Try the supplied transforms and key hints.
	 *
	 * @param encoded encrypted bytes
	 * @param transforms transforms to attempt
	 * @param keyHints key candidates collected from the call graph
	 * @param maxLength maximum number of input bytes to inspect
	 * @param minScore minimum accepted text score
	 * @return the best successful result
	 */
	public static Optional<Decoded> decode(byte[] encoded, List<Transform> transforms,
			List<Key> keyHints, int maxLength, double minScore) {
		if (encoded == null || encoded.length < MIN_STRING_LENGTH || transforms == null ||
			transforms.isEmpty()) {
			return Optional.empty();
		}

		int limit = Math.max(MIN_STRING_LENGTH, Math.min(encoded.length, maxLength));
		byte[] input = Arrays.copyOf(encoded, limit);
		List<Key> hints = normalizeKeys(keyHints);
		Decoded best = null;

		for (Transform transform : transforms) {
			if (transform.usesKey()) {
				for (Key key : hints) {
					best = chooseBest(best,
						decodeWithKey(input, transform, key, minScore));
				}
			}
			else {
				best = chooseBest(best, decodeWithKey(input, transform, null, minScore));
			}
		}

		// A statically recovered key may be incomplete. Brute-force single-byte XOR/add/sub
		// transforms as a fallback; it is cheap and catches the common malware pattern.
		if (best == null) {
			for (Transform transform : transforms) {
				if (!transform.usesKey()) {
					continue;
				}
				for (int value = 1; value < 256; value++) {
					Key key = new Key(new byte[] { (byte) value }, "brute-force");
					best = chooseBest(best, decodeWithKey(input, transform, key, minScore));
				}
			}
		}
		return Optional.ofNullable(best);
	}

	/**
	 * Convenience overload that uses the default string length and confidence.
	 *
	 * @param encoded encrypted bytes
	 * @param transforms transforms to attempt
	 * @param keyHints key candidates
	 * @return best successful result
	 */
	public static Optional<Decoded> decode(byte[] encoded, List<Transform> transforms,
			List<Key> keyHints) {
		return decode(encoded, transforms, keyHints, 512, DEFAULT_MIN_SCORE);
	}

	/**
	 * Apply a transform to a byte array.
	 *
	 * @param data input bytes
	 * @param transform transform to apply
	 * @param key key bytes for XOR/ADD/SUB steps
	 * @return transformed bytes
	 */
	public static byte[] apply(byte[] data, Transform transform, byte[] key) {
		byte[] result = data.clone();
		for (Step step : transform.steps()) {
			switch (step.operation()) {
				case XOR -> applyKeyed(result, key, step.operation());
				case ADD -> applyKeyed(result, key, step.operation());
				case SUB -> applyKeyed(result, key, step.operation());
				case ROL -> rotate(result, step.amount(), true);
				case ROR -> rotate(result, step.amount(), false);
				case NOT -> {
					for (int i = 0; i < result.length; i++) {
						result[i] = (byte) ~result[i];
					}
				}
				case REVERSE -> reverse(result);
			}
		}
		return result;
	}

	private static Decoded decodeWithKey(byte[] encoded, Transform transform, Key key,
			double minScore) {
		byte[] keyBytes = key == null ? null : key.bytes();
		if (transform.usesKey() && (keyBytes == null || keyBytes.length == 0)) {
			return null;
		}

		byte[] transformed = apply(encoded, transform, keyBytes);
		byte[] plaintext = trimAtTerminator(transformed);
		if (plaintext.length < MIN_STRING_LENGTH) {
			return null;
		}

		String text = decodeText(plaintext);
		if (text == null) {
			return null;
		}
		double score = scoreText(plaintext);
		if (score < minScore) {
			return null;
		}
		return new Decoded(plaintext, text, transform, key, score);
	}

	private static Decoded chooseBest(Decoded current, Decoded candidate) {
		if (candidate == null) {
			return current;
		}
		if (current == null || candidate.score() > current.score()) {
			return candidate;
		}
		return current;
	}

	private static void applyKeyed(byte[] data, byte[] key, Operation operation) {
		for (int i = 0; i < data.length; i++) {
			int value = data[i] & 0xff;
			int keyValue = key[i % key.length] & 0xff;
			int transformed = switch (operation) {
				case XOR -> value ^ keyValue;
				case ADD -> (value + keyValue) & 0xff;
				case SUB -> (value - keyValue) & 0xff;
				default -> throw new IllegalArgumentException(operation.toString());
			};
			data[i] = (byte) transformed;
		}
	}

	private static void rotate(byte[] data, int amount, boolean left) {
		int shift = Math.floorMod(amount, 8);
		if (shift == 0) {
			return;
		}
		for (int i = 0; i < data.length; i++) {
			int value = data[i] & 0xff;
			data[i] = (byte) (left ? ((value << shift) | (value >>> (8 - shift))) & 0xff
					: ((value >>> shift) | (value << (8 - shift))) & 0xff);
		}
	}

	private static void reverse(byte[] data) {
		for (int left = 0, right = data.length - 1; left < right; left++, right--) {
			byte tmp = data[left];
			data[left] = data[right];
			data[right] = tmp;
		}
	}

	private static byte[] trimAtTerminator(byte[] data) {
		int end = data.length;
		for (int i = 0; i < data.length; i++) {
			if (data[i] == 0) {
				end = i;
				break;
			}
		}
		while (end > 0 && Character.isWhitespace((char) (data[end - 1] & 0xff))) {
			end--;
		}
		return Arrays.copyOf(data, end);
	}

	private static String decodeText(byte[] data) {
		try {
			return StandardCharsets.UTF_8.newDecoder()
					.onMalformedInput(CodingErrorAction.REPORT)
					.onUnmappableCharacter(CodingErrorAction.REPORT)
					.decode(ByteBuffer.wrap(data))
					.toString();
		}
		catch (CharacterCodingException e) {
			// Most malware strings are byte strings. Latin-1 keeps every byte round-trippable;
			// scoreText() rejects control-heavy/non-text results.
			return new String(data, StandardCharsets.ISO_8859_1);
		}
	}

	private static boolean isValidUtf8(byte[] data) {
		try {
			StandardCharsets.UTF_8.newDecoder()
					.onMalformedInput(CodingErrorAction.REPORT)
					.onUnmappableCharacter(CodingErrorAction.REPORT)
					.decode(ByteBuffer.wrap(data));
			return true;
		}
		catch (CharacterCodingException e) {
			return false;
		}
	}

	/**
	 * Score how much a byte sequence looks like a recovered text string.
	 *
	 * @param data bytes to score
	 * @return score from 0 (not text) to 1 (very likely text)
	 */
	public static double scoreText(byte[] data) {
		if (data == null || data.length < MIN_STRING_LENGTH) {
			return 0.0;
		}
		byte[] plaintext = trimAtTerminator(data);
		if (plaintext.length < MIN_STRING_LENGTH) {
			return 0.0;
		}
		if (!isValidUtf8(plaintext)) {
			for (byte value : plaintext) {
				if ((value & 0x80) != 0) {
					return 0.0;
				}
			}
		}
		String text = decodeText(plaintext);
		if (text == null || text.isEmpty()) {
			return 0.0;
		}
		return scoreText(text);
	}

	private static double scoreText(String text) {
		int printable = 0;
		int letters = 0;
		int digits = 0;
		int spaces = 0;
		int unicodeText = 0;
		int length = text.length();

		for (int i = 0; i < length; i++) {
			char c = text.charAt(i);
			if (c == '\t' || c == '\n' || c == '\r') {
				printable++;
				spaces++;
			}
			else if (c >= 0x20 && c <= 0x7e) {
				printable++;
				if (Character.isLetter(c)) {
					letters++;
				}
				else if (Character.isDigit(c)) {
					digits++;
				}
				else if (Character.isWhitespace(c)) {
					spaces++;
				}
			}
			else if (Character.isLetterOrDigit(c) || Character.isSpaceChar(c)) {
				unicodeText++;
				if (Character.isLetter(c)) {
					letters++;
				}
				else if (Character.isDigit(c)) {
					digits++;
				}
				else {
					spaces++;
				}
			}
			else if (Character.isISOControl(c)) {
				return 0.0;
			}
			else {
				return 0.0;
			}
		}

		double printableRatio = (double) printable / length;
		if (unicodeText > 0) {
			// A valid run of Unicode letters is a strong signal. Keep this path simple because
			// the byte-oriented bigram model below is intentionally ASCII-centric.
			double textCoverage = (double) (printable + unicodeText) / length;
			return Math.min(1.0, 0.92 * textCoverage + 0.08 * ((double) letters / length));
		}

		if (digits == length) {
			return 1.0;
		}

		double letterRatio = (double) letters / length;
		double digitRatio = (double) digits / length;
		double spaceRatio = (double) spaces / length;
		double spaceScore = spaces == 0 ? 0.5 : spaceRatio <= 0.35 ? 1.0 : 0.5;

		String lower = text.toLowerCase(Locale.ROOT);
		int pairs = 0;
		int bigramHits = 0;
		for (int i = 0; i + 1 < lower.length(); i++) {
			char a = lower.charAt(i);
			char b = lower.charAt(i + 1);
			if (Character.isLetter(a) && Character.isLetter(b)) {
				pairs++;
				if (COMMON_BIGRAMS.contains(lower.substring(i, i + 2))) {
					bigramHits++;
				}
			}
		}
		double bigramRatio = pairs == 0 ? 0.0 : (double) bigramHits / pairs;
		double bigramScore = Math.min(1.0, bigramRatio / 0.38);

		int trigramHits = 0;
		int trigrams = 0;
		for (int i = 0; i + 2 < lower.length(); i++) {
			if (Character.isLetter(lower.charAt(i)) &&
				Character.isLetter(lower.charAt(i + 1)) &&
				Character.isLetter(lower.charAt(i + 2))) {
				trigrams++;
				if (COMMON_TRIGRAMS.contains(lower.substring(i, i + 3))) {
					trigramHits++;
				}
			}
		}
		double trigramScore = trigrams == 0 ? 0.0
				: Math.min(1.0, ((double) trigramHits / trigrams) / 0.25);

		int tokenHits = 0;
		for (String token : COMMON_TOKENS) {
			if (lower.contains(token)) {
				tokenHits++;
			}
		}
		double tokenScore = Math.min(1.0, tokenHits / 2.0);

		int wordCount = 0;
		int knownWords = 0;
		for (String word : lower.split("[^a-z]+")) {
			if (word.length() < 2) {
				continue;
			}
			wordCount++;
			if (COMMON_WORDS.contains(word)) {
				knownWords++;
			}
		}
		double wordScore = wordCount == 0 ? 0.0 : (double) knownWords / wordCount;

		int malformedTokens = 0;
		int tokens = 0;
		for (String token : text.split("\\s+")) {
			if (token.isEmpty()) {
				continue;
			}
			tokens++;
			for (int i = 0; i < token.length(); i++) {
				char c = token.charAt(i);
				if (Character.isLetterOrDigit(c) || "._:/\\-=+*#$%&@!?,;'\"()<>".indexOf(c) >= 0) {
					continue;
				}
				malformedTokens++;
				break;
			}
		}
		double malformedRatio = tokens == 0 ? 0.0 : (double) malformedTokens / tokens;

		double score = 0.28 * printableRatio +
			0.07 * letterRatio +
			0.04 * digitRatio +
			0.07 * spaceScore +
			0.22 * bigramScore +
			0.08 * trigramScore +
			0.18 * wordScore +
			0.06 * tokenScore -
			0.04 * malformedRatio;
		return Math.max(0.0, Math.min(1.0, score));
	}

	private static List<Operation> normalizeOperations(List<Operation> operations) {
		if (operations == null) {
			return List.of();
		}
		List<Operation> result = new ArrayList<>();
		for (Operation operation : operations) {
			if (operation != null &&
				(result.isEmpty() || result.get(result.size() - 1) != operation)) {
				result.add(operation);
			}
		}
		return result;
	}

	private static List<Key> normalizeKeys(List<Key> keys) {
		if (keys == null) {
			return List.of();
		}
		LinkedHashMap<String, Key> result = new LinkedHashMap<>();
		for (Key key : keys) {
			if (key == null || key.bytes().length == 0) {
				continue;
			}
			String id = Base64.getEncoder().encodeToString(key.bytes());
			result.putIfAbsent(id, key);
		}
		return List.copyOf(result.values());
	}

	private static void addIndividualTransforms(Map<String, Transform> transforms,
			Operation operation) {
		switch (operation) {
			case ROL, ROR -> {
				for (int amount = 1; amount < 8; amount++) {
					addTransform(transforms, List.of(new Step(operation, amount)));
				}
			}
			case REVERSE -> addTransform(transforms,
				List.of(new Step(Operation.REVERSE, 0)));
			default -> addTransform(transforms, List.of(new Step(operation, 0)));
		}
	}

	private static void addExpandedSequence(Map<String, Transform> transforms,
			List<Operation> sequence) {
		long combinations = 1;
		for (Operation operation : sequence) {
			if (operation == Operation.ROL || operation == Operation.ROR) {
				combinations *= 7;
			}
		}
		boolean useDefaultAmounts = combinations > MAX_EXPANDED_TRANSFORMS;

		List<List<Step>> partial = new ArrayList<>();
		partial.add(new ArrayList<>());
		for (Operation operation : sequence) {
			List<Step> choices;
			if (operation == Operation.ROL || operation == Operation.ROR) {
				if (useDefaultAmounts) {
					choices = List.of(new Step(operation, 1));
				}
				else {
					choices = new ArrayList<>();
					for (int amount = 1; amount < 8; amount++) {
						choices.add(new Step(operation, amount));
					}
				}
			}
			else {
				choices = List.of(new Step(operation, 0));
			}

			List<List<Step>> next = new ArrayList<>();
			for (List<Step> prefix : partial) {
				for (Step choice : choices) {
					List<Step> expanded = new ArrayList<>(prefix);
					expanded.add(choice);
					next.add(expanded);
				}
			}
			partial = next;
		}
		for (List<Step> steps : partial) {
			addTransform(transforms, steps);
		}
	}

	private static void addTransform(Map<String, Transform> transforms, List<Step> steps) {
		if (steps.isEmpty()) {
			return;
		}
		StringBuilder label = new StringBuilder();
		for (Step step : steps) {
			if (label.length() > 0) {
				label.append('+');
			}
			label.append(step.operation());
			if (step.operation() == Operation.ROL || step.operation() == Operation.ROR) {
				label.append(step.amount());
			}
		}
		String key = steps.toString();
		transforms.putIfAbsent(key, new Transform(steps, label.toString()));
	}
}
