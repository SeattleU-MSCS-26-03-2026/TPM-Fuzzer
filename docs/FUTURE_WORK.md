# Future Work

This document captures all the future work that would improve the TPM fuzzing framework. The focus is on expanding command coverage improving confidence in the fuzzing infrastructure, and making the framework more reusable across TPM backends.

## Priorities

The current priorities are:
1. Expand the seed corpus for both byte-level and structure-aware fuzzing
2. Add stronger automated testing around seed generation and marshaling
3. Improve the performance for proto fuzzer conversion and post-processing pipeline
4. Broaden support for additional TPM implementations
5. Improve continuous fuzzing workflows and coverage visibility

## Seed Corpus Expansion

The current corpus should continue to grow in both the bytearray and protobuf seed sets.

Areas of work:
- Add more seeds for supported TPM commands in both `seeds/bytearray/` and `seeds/proto/`
- Add more multi-command sequences that exercise state transitions, object lifecycles, sessions, and policy-dependent flows
- Add more negative and edge-case seeds that intentionally target rejection paths and error handling
- Expand seed coverage across more TPM subsystems such as PCR, NV, object management, sessions, cryptographic operations, and policy commands

## Testing and Validation

More of the framework should be exercised by automated tests rather than manual inspection and ad hoc seed execution.

Areas of work:
- Add unit tests for harness components such as `src/harness/proto_conversion.cc`, `src/harness/proto_normalization.cc`, `src/harness/proto_postprocessors.cc`, and TPM wrapper logic
- Add unit tests for parser components such as `src/parser/byte_parser.cc`
- Add regression tests based on the unit tests.
- Add end-to-end tests for representative command sequences against the harness
- Add checks that generated protobuf artifacts are up to date with the checked-in `.proto` definitions

## Proto Fuzzer Improvements

The structure-aware fuzzer should continue to evolve so that mutated protobuf inputs remain meaningful and reach deeper execution paths.

Areas of work:
- Improve the generic conversion logic in `proto_conversion.cc` to better handle additional TPM field layouts and command shapes
- Add more command-specific post-processors for newly supported protobuf commands
- Improve normalization defaults for handles, sessions, headers, and algorithm selections
- Add better debugging support for failed marshaling and invalid structured inputs
- Review schema consistency across proto commands, especially where reserved handles and constrained enums should be represented more strongly

### Session Authorization Layer

The current session authorization layer already allows the proto fuzzer to get past basic TPM authorization checks for supported HMAC-session flows. Future work in this area should improve both coverage and robustness without changing the layer's goal of minimally patching fuzzer-produced commands.

Areas of work:
- Expand support beyond the current null-salt, no-bind HMAC session path
- Add support for more negotiated hash algorithms beyond SHA-256
- Make HMAC size and digest handling follow the negotiated session hash rather than assuming SHA-256 everywhere
- Improve recovery and diagnostics when stale `nonceTPM`, missing handle Names, or unsupported commands cause cascading authorization failures
- Expand command coverage in the session auth path so more session-authorized commands can be patched successfully
- Add tests for session bootstrapping, nonce refresh, Name table updates, and HMAC patching behavior

### Broader Session Support

The current implementation is centered on HMAC sessions. Future work may extend the framework's ability to reason about and validate other TPM session models.

Areas of work:
- Evaluate support for Policy and Trial session flows where they are useful for structured fuzzing
- Evaluate support for salted and bound HMAC sessions instead of only null-salt, no-bind sessions
- Improve handling of session attributes such as `decrypt`, `encrypt`, and `audit`
- Explore limited support for parameter encryption and decryption flows used by session-based authorization
- Improve support for tracking more than one active session when command sequences require it

## TPM Backend Support

The framework is designed to support more than the default TPM reference implementation, but this should be strengthened and exercised more thoroughly.

Areas of work:
- Add support for more TPM implementations beyond the current reference target
- Improve wrapper abstractions so alternative TPM backends can be plugged in with less custom effort
- Document backend-specific assumptions and incompatibilities
- Add backend-specific tests to ensure that common fuzzing workflows still behave correctly
- Compare coverage and behavior differences across TPM implementations

## Continuous Fuzzing and Coverage

The project already has a basic workflow for running fuzzing in GCP, along with GitHub Actions support to push and integrate with that environment. However, continuous fuzzing is not the main focus of the current project. The primary goal at this stage is to make sure the framework itself works correctly, including the harness, seed generation, command support, and structured fuzzing pipeline.
Future work in this area should focus on improving the existing workflow so it becomes more seamless, easier to operate, and better suited for long-running coverage-driven fuzzing.

Potential areas of work:
- Improve the existing continuous fuzzing setup used by both `fuzzer` and `proto-fuzzer`
- Make the GCP deployment and execution flow more seamless from GitHub Actions
- Improve automation for build, upload, run, and result collection steps
- Reduce manual coordination required to launch, monitor, and triage fuzzing runs in GCP
- Add coverage reporting workflows that make command-level and subsystem-level gaps easy to identify
- Track coverage changes over time to measure whether new seeds and proto schemas are actually improving exploration
- Improve retention and triage of crash artifacts, minimized reproducers, and useful generated corpus entries
- Define target coverage goals for critical TPM areas and use them to drive future seed work

## Longer-Term Technical Debt

There are also structural improvements that may reduce maintenance cost over time.

Areas of work:
- Reduce duplication between Python command serialization logic and C++ marshaling logic
- Evaluate whether parts of the TPM command wrappers can be generated rather than maintained by hand
- Standardize proto schema choices for similar TPM concepts across commands
- Revisit checked-in generated artifacts and make regeneration expectations more explicit in the developer workflow
