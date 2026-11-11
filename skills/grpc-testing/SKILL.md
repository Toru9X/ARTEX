---
name: grpc-testing
description: "Testing gRPC and gRPC-Web services: enumerating methods through server reflection or a leaked .proto/descriptor, calling them directly with grpcurl to bypass authorization enforced only in the REST gateway, and finding BOLA/BFLA in services whose methods were never meant to be client-reachable. Use when traffic shows application/grpc or application/grpc-web content types, a :authority or grpc-status header, a port like 50051, an envoy/grpc-gateway in front of the API, or a mobile app that talks protobuf instead of JSON."
---

# gRPC / gRPC-Web Testing

gRPC endpoints are routinely left out of scope by accident: a proxy records them as unreadable binary, scanners skip them, and the team assumes the REST gateway is the only door. It usually is not.

## Crown Jewel Targets

- **Gateway bypass** — authorization implemented in the REST/grpc-gateway layer while the gRPC port accepts unauthenticated calls directly
- **Unexposed methods** — admin or internal RPCs present in the service definition that no client ever calls
- **BOLA on a resource id** — the same object-id substitution as REST, in a protobuf field
- **Reflection left enabled in production** — hands you the full API surface

## Attack Surface Signals

- `content-type: application/grpc` or `application/grpc-web+proto` in recorded traffic
- `grpc-status` / `grpc-message` response headers, HTTP/2 with `:path` of `/package.Service/Method`
- A `.proto`, `*_pb2.py`, `*_pb.js`, or a descriptor set reachable in a JS bundle or mobile package
- An Envoy or grpc-gateway banner; port 50051, 8080 with h2c

## Method

1. **Try reflection first.** `grpcurl -plaintext host:50051 list` then `grpcurl -plaintext host:50051 list package.Service` and `describe` for the message shapes. TLS: drop `-plaintext`.
2. **If reflection is off**, recover the schema from the client: pull the JS bundle or the APK and look for `_pb.js`/`_pb2.py`/descriptors. Feed a recovered `.proto` with `-import-path` and `-proto`.
3. **Call the method directly**, outside the gateway: `grpcurl -plaintext -d '{"id":1}' host:50051 package.Service/GetItem`. Compare what the REST route returns for the same id with what the raw gRPC call returns — a difference is the gateway doing authorization the service does not.
4. **Carry the credential across.** `-H 'authorization: Bearer ...'`. Then re-run with the header removed, and with a *different* user's token, to separate "no authz" from "wrong authz".
5. **Walk object ids** on every method that takes one. This is BOLA; the protobuf wrapper changes nothing about the logic.
6. **gRPC-Web** rides over normal HTTP/1.1 and is reachable with `curl.exe`; the body is a length-prefixed protobuf frame, so replay captured requests and mutate the field bytes rather than hand-writing one.

On this host remember the shell rules: single-quote the `-d` JSON, and never pipe a target list into a tool.

## Evidence That Survives Triage

The paired request/response: the REST call that correctly denies you, and the direct gRPC call that returns the same resource. Include the method's full path (`/package.Service/Method`) and the identity used, so the reviewer can tell gateway-bypass from a method that is intentionally public.

## Common False Positives

- Reflection enabled on a staging host that is in scope but carries no real data — still report, lower severity
- A method that returns data your own account is entitled to anyway
- `grpc-status: 12 UNIMPLEMENTED` read as a block; it means the method does not exist

See [[api-security-testing]], [[access-control-testing]], [[mobile-api-testing]].
