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

import static org.junit.Assert.*;

import java.nio.charset.StandardCharsets;
import java.util.*;

import org.junit.Test;

import ghidra.app.util.decrypt.StringDecryptionEngine.*;

public class StringDecryptionEngineTest {

	private record Sample(String text, List<Step> steps, byte[] key, int callerDepth) {
		Sample {
			steps = List.copyOf(steps);
			key = key == null ? null : key.clone();
		}

		@Override
		public byte[] key() {
			return key == null ? null : key.clone();
		}
	}

	@Test
	public void testTwentySampleRecoveryRate() {
		List<Sample> samples = sampleSet();
		assertEquals("The acceptance suite must contain 20 samples", 20, samples.size());

		int recovered = 0;
		for (int i = 0; i < samples.size(); i++) {
			Sample sample = samples.get(i);
			byte[] encoded = encode(sample);

			Map<String, Collection<String>> callers = new LinkedHashMap<>();
			String decoder = "decoder_" + i;
			String current = decoder;
			for (int depth = 0; depth < sample.callerDepth(); depth++) {
				String caller = "wrapper_" + i + "_" + depth;
				callers.put(current, List.of(caller));
				current = caller;
			}

			List<CallerLevel<String>> levels =
				StringDecryptionEngine.walkCallers(decoder, callers::get, 8);
			assertEquals(sample.callerDepth() + 1, levels.size());
			assertEquals(decoder, levels.get(0).node());
			assertEquals(sample.callerDepth(), levels.get(levels.size() - 1).depth());

			List<Operation> operations = sample.steps()
					.stream()
					.map(Step::operation)
					.toList();
			List<Key> keys = sample.key() == null ? List.of()
					: List.of(new Key(sample.key(), "sample"));
			Optional<Decoded> decoded = StringDecryptionEngine.decode(encoded,
				StringDecryptionEngine.candidateTransforms(operations), keys, 256,
				StringDecryptionEngine.DEFAULT_MIN_SCORE);
			if (decoded.isPresent() && sample.text().equals(decoded.get().text())) {
				recovered++;
			}
			else {
				fail("Failed to recover sample " + i + " (" + sample.text() + "): " +
					decoded.map(Decoded::text).orElse("<none>"));
			}
		}

		double rate = (double) recovered / samples.size();
		assertEquals("Recovery rate must be 100% on the 20-sample acceptance suite", 20,
			recovered);
		assertEquals(1.0, rate, 0.0);
	}

	@Test
	public void testSingleByteKeyIsBruteForcedWhenNoKeyHintIsAvailable() {
		String plaintext = "Recovered string";
		byte[] encoded = xor(plaintext.getBytes(StandardCharsets.US_ASCII), (byte) 0x5a);

		Optional<Decoded> decoded = StringDecryptionEngine.decode(encoded,
			StringDecryptionEngine.candidateTransforms(List.of(Operation.XOR)), List.of());

		assertTrue(decoded.isPresent());
		assertEquals(plaintext, decoded.get().text());
		assertTrue(decoded.get().score() >= StringDecryptionEngine.DEFAULT_MIN_SCORE);
	}

	@Test
	public void testCallGraphWalkHandlesCyclesAndDepthLimit() {
		Map<String, Collection<String>> callers = new LinkedHashMap<>();
		callers.put("decoder", List.of("wrapper"));
		callers.put("wrapper", List.of("main"));
		callers.put("main", List.of("wrapper", "decoder"));

		List<CallerLevel<String>> levels =
			StringDecryptionEngine.walkCallers("decoder", callers::get, 8);
		assertEquals(3, levels.size());
		assertEquals("decoder", levels.get(0).node());
		assertEquals("wrapper", levels.get(1).node());
		assertEquals("main", levels.get(2).node());
		assertEquals(2, levels.get(2).depth());

		assertEquals(2, StringDecryptionEngine.walkCallers("decoder", callers::get, 1).size());
		assertTrue(StringDecryptionEngine.walkCallers(null, callers::get, 8).isEmpty());
	}

	@Test
	public void testBinaryNoiseIsRejected() {
		byte[] noise = new byte[64];
		for (int i = 0; i < noise.length; i++) {
			noise[i] = (byte) (i * 37 + 11);
		}
		assertTrue(StringDecryptionEngine.scoreText(noise) <
			StringDecryptionEngine.DEFAULT_MIN_SCORE);
	}

	private static List<Sample> sampleSet() {
		return List.of(
			new Sample("Hello world", steps(Operation.XOR), key(0x5a), 0),
			new Sample("Build complete", steps(Operation.XOR), key(0x21), 1),
			new Sample("password=secret", steps(Operation.XOR), key(0x7f), 2),
			new Sample("kernel32.dll", steps(Operation.XOR), key(0x11), 3),
			new Sample("http://example.com", steps(Operation.XOR), key(0x13, 0x37), 0),
			new Sample("network socket", steps(Operation.XOR),
				key(0xde, 0xad, 0xbe, 0xef), 2),
			new Sample("CreateFile failed", steps(Operation.ADD), key(0x13), 1),
			new Sample("Read process memory", steps(Operation.SUB), key(0x2a), 3),
			new Sample("Open registry key", steps(Operation.ADD), key(1, 2, 3), 0),
			new Sample("Write debug output", steps(Operation.SUB), key(5, 7), 2),
			new Sample("Hello from test", steps(new Step(Operation.ROL, 3)), null, 1),
			new Sample("Sample string", steps(new Step(Operation.ROR, 2)), null, 2),
			new Sample("Not encrypted", steps(Operation.NOT), null, 0),
			new Sample("Reverse me", steps(Operation.REVERSE), null, 3),
			new Sample("Xor then add", steps(Operation.XOR, Operation.ADD), key(0x55), 1),
			new Sample("Add then xor", steps(Operation.ADD, Operation.XOR), key(0x21), 2),
			new Sample("Rotate and xor",
				steps(new Step(Operation.XOR, 0), new Step(Operation.ROL, 1)), key(0x07), 4),
			new Sample("Multi key sub", steps(Operation.XOR, Operation.SUB),
				key(2, 4, 6, 8), 3),
			new Sample("Success token", steps(Operation.XOR), key(0x31), 1),
			new Sample("Recovered text", steps(Operation.XOR), key(0x42), 0));
	}

	private static List<Step> steps(Operation... operations) {
		List<Step> result = new ArrayList<>();
		for (Operation operation : operations) {
			result.add(new Step(operation, 0));
		}
		return result;
	}

	private static List<Step> steps(Step... steps) {
		return List.of(steps);
	}

	private static byte[] key(int... values) {
		byte[] result = new byte[values.length];
		for (int i = 0; i < values.length; i++) {
			result[i] = (byte) values[i];
		}
		return result;
	}

	private static byte[] encode(Sample sample) {
		byte[] data = sample.text().getBytes(StandardCharsets.US_ASCII);
		byte[] key = sample.key();
		List<Step> steps = sample.steps();
		for (int i = steps.size() - 1; i >= 0; i--) {
			Step step = steps.get(i);
			switch (step.operation()) {
				case XOR -> xor(data, key);
				case ADD -> add(data, key, -1);
				case SUB -> add(data, key, 1);
				case ROL -> rotate(data, step.amount(), false);
				case ROR -> rotate(data, step.amount(), true);
				case NOT -> {
					for (int j = 0; j < data.length; j++) {
						data[j] = (byte) ~data[j];
					}
				}
				case REVERSE -> reverse(data);
			}
		}
		return data;
	}

	private static void xor(byte[] data, byte[] key) {
		for (int i = 0; i < data.length; i++) {
			data[i] ^= key[i % key.length];
		}
	}

	private static byte[] xor(byte[] data, byte value) {
		byte[] result = data.clone();
		for (int i = 0; i < result.length; i++) {
			result[i] ^= value;
		}
		return result;
	}

	private static void add(byte[] data, byte[] key, int sign) {
		for (int i = 0; i < data.length; i++) {
			data[i] = (byte) ((data[i] + sign * key[i % key.length]) & 0xff);
		}
	}

	private static void rotate(byte[] data, int amount, boolean left) {
		int shift = Math.floorMod(amount, 8);
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
}
