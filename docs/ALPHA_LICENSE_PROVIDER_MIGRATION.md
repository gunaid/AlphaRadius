# Alpha Radius license-provider migration

## Goal

New installations use the Aman license authority at `https://ls.amtik.online`
without invalidating license files issued by the original Alpha authority.

## Trust model

`core/licensing.py` pins two independent Ed25519 public keys:

- `aman-alpha`: current Aman packages and signed heartbeat responses.
- `legacy-alpha`: packages issued before the Aman migration.

The matching cryptographic signature determines the authority. A field inside
the package cannot select or downgrade the authority, and unknown signatures
remain rejected.

## Runtime behavior

Current Aman packages:

- require activation and signed heartbeats through `ls.amtik.online`;
- retain the existing 24-hour network grace policy;
- accept signed suspend, revoke, unlicensed, sync and binding-error responses;
- receive package/quota/feature updates through the existing OTA path.

Legacy packages:

- retain the original public key, machine/instance binding, expiry, quotas and
  feature checks;
- remain subject to the local revocation list and explicit suspended/revoked
  database states;
- do not contact the Aman server, because an unimported legacy identifier would
  be reported as unlicensed;
- ignore only the old network-derived `grace_expired` state. This prevents a
  retired legacy endpoint from disabling an otherwise valid signed package.

Legacy licenses do not gain Aman remote control automatically. To migrate one,
issue and install a new Aman-signed package for the same customer and binding.
That replacement switches the installation to managed heartbeats because the
authority is derived from the new signature.

## Safe rollout

1. Back up `wisp_license_info`, `wisp_revoked_licenses`,
   `wisp_license_runtime_state`, and the persistent `storage/secrets` directory.
2. Deploy the code without replacing existing `.lic` files.
3. Confirm an old package reports `license_authority=legacy-alpha`, remains
   locally valid, and does not send a heartbeat to Aman.
4. Confirm an Aman package reports `license_authority=aman-alpha` and completes
   a signed heartbeat with `ls.amtik.online`.
5. Migrate old customers one at a time by installing a newly issued Aman
   package. Never rewrite or re-sign an old package in place.

## Isolated verification

```text
python -B -m unittest \
  tests.test_alpha_dual_license_provider \
  tests.test_license_activation -v
```

These checks use generated fixture keys and mocked storage/network boundaries;
they do not activate, revoke or modify a real customer license.
