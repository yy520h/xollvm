# Cloud Material Backend Task 1 Report

## Scope

Task 1 establishes the standalone C++ backend build, canonical request parsing, and relay-envelope parsing. The backend test executable is registered with CTest and uses a local named-test/assertion harness; GoogleTest and other external test frameworks are not required.

## Findings and Fix

The first CTest run configured and built successfully, then reported 10 passing cases and one failure: `RelayEnvelopeReturnsExactRequestBytes`. Temporary failure diagnostics exposed `BackendError{"invalid_json"}`. In nlohmann JSON's parser callback, the `key` event depth is one greater than its containing `object_start` depth. The duplicate-key callback indexed the key set using the unadjusted depth, so every top-level envelope key looked like a duplicate. `http_contract.cpp` now indexes the containing object with `depth - 1`.

The regression test verifies a valid relay envelope succeeds and returns the exact original canonical request bytes. Existing tests continue to reject duplicate envelope fields, malformed/noncanonical Base64, and unknown envelope fields.

Independent review found the envelope DOM parser lacked a nesting bound. Added a 300-level nested-array case requiring `json_depth_limit`; it failed before the pre-scan was invoked and passed after adding a lexical depth-one pre-scan before DOM construction. The pre-scan ignores delimiters inside escaped JSON strings. Review also found Boost discovery/linkage was unused in Task 1; it has been removed, and HTTP server dependency selection is deferred to Task 5.

## TDD Evidence

RED, before the parser fix:

```text
relay envelope rejected: invalid_json
.../utils/CloudMaterialBackendProtocolTest.cpp:220: ! (rejected(parsed)) failed in RelayEnvelopeReturnsExactRequestBytes
[FAIL] RelayEnvelopeReturnsExactRequestBytes
10 other named cases passed
11 tests, 22 assertions, 1 failures
CTest: 0% tests passed, 1 tests failed out of 1
```

GREEN, after the parser fix, direct named-test output:

```text
[PASS] AcceptsSessionOpenAndPreservesCanonicalBytes
[PASS] AcceptsMaterialIssue
[PASS] AcceptsSessionRenewAndClose
[PASS] RejectsUnknownAndMissingFields
[PASS] RejectsDuplicateFields
[PASS] RejectsInvalidUtf8
[PASS] RejectsNoncanonicalEncoding
[PASS] RejectsUnsupportedSuiteAndOversizedRequest
[PASS] RelayEnvelopeReturnsExactRequestBytes
[PASS] RelayEnvelopeRejectsDuplicateFieldsAndBadBase64
[PASS] RelayEnvelopeRejectsUnknownFields
11 tests, 23 assertions, 0 failures
```

GREEN, CTest:

```text
Test project .../build/cloud_material_backend
    Start 1: xovm-cloud-material-backend-tests
1/1 Test #1: xovm-cloud-material-backend-tests ...   Passed    0.01 sec

100% tests passed, 0 tests failed out of 1
```

Review-fix RED, with the deep-nesting regression added but pre-scan not invoked:

```text
RelayEnvelopeRejectsExcessiveNestingBeforeJsonParse:
expected BackendError.code == "json_depth_limit"
11 tests, 25 assertions, 1 failure
```

Review-fix GREEN, after wiring in the bounded pre-scan:

```text
12 tests, 25 assertions, 0 failures
CTest: 1/1 passed, 100% tests passed
```

Commands used:

```sh
cmake -S runtime/cloud_material_backend -B build/cloud_material_backend -DBUILD_TESTING=ON
cmake --build build/cloud_material_backend --target xovm-cloud-material-backend-tests
ctest --test-dir build/cloud_material_backend --output-on-failure
build/cloud_material_backend/xovm-cloud-material-backend-tests
```

The backend parser build no longer discovers or links Boost. The HTTP server library must be selected and discovered by Task 5.

## Contract Review

The inspected parser enforces the relay-body and nesting-depth limits before JSON DOM parsing, exact closed envelope fields, the relay protocol identifier, string type for `request_b64`, strict Base64 alphabet/padding/unused-bit checks, the decoded request limit, and full canonical request/schema validation. The returned relay request is the decoded original byte vector, not a reserialized JSON value. The 12 named cases cover valid request types, unknown/missing/duplicate fields, invalid UTF-8, noncanonical request bytes, unsupported suite, request size, relay byte preservation, duplicate envelope fields, malformed Base64, unknown envelope fields, and excessive nesting.

## Status

Task 1's standalone protocol test target passes. This report does not claim completion of later backend tasks or production deployment validation.
