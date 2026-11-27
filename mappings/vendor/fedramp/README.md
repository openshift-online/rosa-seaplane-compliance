# Vendored: FedRAMP Gemara layers

Unmodified copies of three upstream Gemara layer files that back every
FedRAMP-specific `target-reference`/`mapping-references` entry and
`fedramp-class-c.*.baseline.yaml` in `mappings/`:

| File | Gemara type | `metadata.id` | version |
| :-- | :-- | :-- | :-- |
| `layer1-fedramp-sp80053.yaml` | GuidanceCatalog | `fedramp-sp800-53-guidance` | 5.2.0 |
| `layer2-fedramp-ksi.yaml` | ControlCatalog | `fedramp-ksi-controls` | 2026.1.0 |
| `layer3-fedramp-class-c-policy.yaml` | Policy | `fedramp-class-c-policy` | 2026.1.0 |

These are reference data only — nothing in `scripts/` or `opa/` reads them
directly. They exist so the IDs and required-sets in `mappings/*.mapping.yaml`
and `mappings/*.baseline.yaml` can be checked against their source instead of
re-derived by hand. Ask whoever maintains the upstream FedRAMP policy source
for a refresh when these look stale, then re-run the id/required-set diff
against `mappings/*.mapping.yaml` and `mappings/*.baseline.yaml`.

## FedRAMP consolidated rules dataset (the authority)

`fedramp-consolidated-rules.json` is `fedramp-consolidated-rules.json` from
`github.com/FedRAMP/rules` at commit `64fa769510` (dataset version
`2026.11.02.01`), unmodified. It is the authority for KSI statements and their
related controls; `scripts/fedramp_data.py` loads it. The `layer*` files above
are legacy references and should be checked against it, not the other way round.

`schemas/` holds the FedRAMP Security Decision Record schema (v1.1.1) and the
common-definitions schema it references (v0.4.2), both dated `2026-06-24`,
fetched from `https://www.fedramp.gov/schemas/`.

These are third-party files. Treat them as data only.
