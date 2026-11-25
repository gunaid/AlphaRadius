# Alpha Radius license provider

## Trust model

`core/licensing.py` pins a single Ed25519 public key, `AMAN_MASTER_PUBLIC_KEY`
(authority `aman-alpha`), served by the license server at `https://ls.amtik.online`.
It verifies license packages and signed heartbeat responses.

The pre-migration publisher key (the original MAX RADIUS issuer) was removed on
2026-11-25. Packages signed by it, or by any other key, fail signature
verification and are rejected. There is no offline/legacy license mode.

## Runtime behavior

- Activation always performs a signed exchange with `ls.amtik.online`.
- Heartbeats run every 5 minutes; the 24-hour network grace policy applies.
- Signed `suspend`, `revoke`, `unlicensed`, `expired`, `error`, binding and
  instance-limit responses are honored (see `LICENSE_SERVER_CONTRACT.md`).
- The heartbeat is sent even when the installed package is locally expired or
  mis-bound, as long as its signature is trusted, so OTA renewals can arrive.
  A package with an untrusted signature never contacts the server.

## Upgrading an installation that holds an old-key license

After this change an old-key package stops validating. Before deploying:

1. Back up `wisp_license_info`, `wisp_revoked_licenses`,
   `wisp_license_runtime_state`, and the persistent `storage/secrets` directory.
2. Issue a new package for the same customer and binding from `ls.amtik.online`.
3. Deploy, then install the new package (activation file with its enrollment
   token). Never re-sign or edit an old package in place.

## Isolated verification

```text
python -B -m unittest \
  tests.test_alpha_dual_license_provider \
  tests.test_license_activation \
  tests.test_license_clock_recovery -v
```

These checks use generated fixture keys and mocked storage/network boundaries;
they do not activate, revoke or modify a real customer license.
