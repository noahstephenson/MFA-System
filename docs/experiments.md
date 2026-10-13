# Experiments

The experiment harness measures access scope and audit behavior across the three tiers. It uses the same service path as a normal access request, with the hardware boundary mocked.

## Run

From `django_app/`, with the virtual environment active:

```bash
python manage.py run_experiments
```

The command prints its tables and rewrites [`experiments/run_experiments_results.json`](experiments/run_experiments_results.json). It creates and destroys a scratch test database; it does not use `db.sqlite3`. No sensors, Node-RED instance, or network connection are required.

To compare the output with the committed results:

```bash
git diff -- ../docs/experiments/run_experiments_results.json
```

No diff means the regenerated file matches the committed results.

## Fixture and scenarios

The main fixture has twenty protected resources. The first ten require Tier 1, and the last five allow degraded access. These sets are disjoint because a resource requiring assurance above Tier 3 cannot also be reached in Tier 3. Every resource has an active policy for each tier.

The adversary holds a cloned RFID badge and a known PIN, with no enrolled fingerprint. The legitimate subject holds all three factors.

| Scenario | Subject | Asserted tier | Minimum-tier check |
|---|---|---|---|
| S1 | Adversary | Tier 2 | Off |
| S2 | Adversary | Tier 2 | On |
| S3 | Adversary | Tier 3 | On |
| S4 | Legitimate control | Tier 1 | On |

Each attempt calls `run_node_red_access_attempt`. The harness mocks `core.services.node_red_client.collect_factors` and, for the mid-request audit failure, `core.services.create_audit_event`.

## Settings used by the harness

These are Django settings in `django_app/mfa_project/settings.py`, not environment variables. The harness changes them with `override_settings`.

| Setting | Default | Behavior |
|---|---|---|
| `SCOPE_MONOTONICITY_ENABLED` | `True` | Deny access below the resource minimum tier |
| `FAIL_CLOSED_AUDIT_ENABLED` | `True` | An approval stands only if its `access_granted` audit event is written |
| `AUDIT_SINK_AVAILABLE` | `True` | Setting this to `False` makes every audit write fail |

Disabling the first two settings reproduces earlier behavior for comparison.

## Results

With the audit sink available and the decision record required:

| Scenario | Resources reached, out of 20 |
|---|---|
| S1, no minimum-tier check | 20 |
| S2, minimum-tier check | 10 |
| S3, degraded scope | 5 |
| S4, legitimate Tier 1 control | 20 |

The minimum-tier coverage sweep holds S2 constant while varying how many resources require Tier 1:

| Resources requiring Tier 1 | 0 | 5 | 10 | 15 | 20 |
|---|---|---|---|---|---|
| Resources reached | 20 | 15 | 10 | 5 | 0 |

The harness also computes scope overlap from the policy configuration, both with no resource requiring Tier 1 and with ten requiring it.

## Audit failures

The outage matrix runs every scenario with the audit sink available or unavailable and the decision record required or optional. When the sink is unavailable from the start, the session-start audit write fails before an approval can be made.

The separate mid-request failure lets `session_started` be written, then fails every later audit write. This produces the unaudited approvals described in the paper:

| Scenario | Decision record optional | Decision record required |
|---|---|---|
| S1 | 20 | 0 |
| S2 | 10 | 0 |
| S3 | 5 | 0 |
| S4 | 20 | 0 |

With the record optional, Tiers 1 and 2 save the approval and then raise on the failed audit write. Tier 3 suppresses the failure. Requiring the record changes the session to denied when the write fails. This prevents unaudited approvals but also denies the legitimate control while the sink is failing.

## Measurement limits

The results describe authorization decisions against database records. They do not measure enforcement at a physical door or operational endpoint. Sensor inputs are mocked, degradation is configured, and audit failures are injected.

The asserted tier is checked for a valid label but is not bound to observed operating conditions. A subject with RFID and PIN can assert Tier 2 during degradation and receive its broader scope.

Minimum assurance and degraded access remain incompatible on a resource whose minimum is above Tier 3. The fixture keeps those resource sets disjoint. The legitimate control measures ten resources requiring Tier 1; it does not measure legitimate access at full coverage.

The audit guarantee covers approved access decisions. Denials, session-start records, and intermediate audit events can still be lost when the sink is down.

## Model and code

The SysML model governs tier definitions and access logic. The [V4 model archive](local_reference/Tiered_MFA_MBSE_Definitive_Version_V4.mdzip) is the current published archive, and [V3](local_reference/Tiered_MFA_MBSE_Definitive_Version_V3.mdzip) is retained as the previous version. Both open in Cameo Systems Modeler / MagicDraw.

The published V4 archive predates `ProtectedResource.minimum_tier`, which was added in code through migration 0008. The field gives each resource a minimum assurance requirement.
