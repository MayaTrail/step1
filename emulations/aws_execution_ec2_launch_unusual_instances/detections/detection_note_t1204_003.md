# Detection Note — T1204.003 (Launch Unusual EC2 Instance Types for Cryptomining)

**Signal:** `ec2:RunInstances` with a GPU/accelerated instance type outside the
account baseline, by a principal with no ML or rendering workload.

**Instance type is the discriminator.** `RunInstances` fires on every autoscale
event, CI job and deploy. An event-name match cannot distinguish a mining
launch from normal capacity — which is precisely what the original rule tried
to do, while also matching `DescribeImages` and `TerminateInstances`. Both are
dropped as triggers here.

**Family accuracy matters for the verdict:**

| Family | Nature | Reading |
|---|---|---|
| `p*`, `g*` | GPU | Mining-capable — the real signal |
| `f*` | FPGA | Unusual; investigate |
| `inf*`, `trn*`, `dl*` | ML accelerators | **Not** mining-capable — cost-abuse signal only |

Lumping the ML accelerators in with GPU families overstates the finding. The
queries here separate them in the verdict.

**Three layers, in increasing order of certainty:**

1. **Control plane** — a GPU instance was launched (inference).
2. **Cost Anomaly Detection** — spend spiked (corroboration).
3. **GuardDuty `CryptoCurrency:EC2/*`** — mining traffic observed
   (confirmation). This is the definitive runtime signal and was absent from
   the original detection set entirely.

**Failed launches are their own signal.** An actor discovering which types a
credential can launch produces a burst of failures. Match the full failure set
— `VcpuLimitExceeded`, `InstanceLimitExceeded`, `InsufficientInstanceCapacity`,
`Unsupported`, `InvalidParameterValue`. A `LimitExceeded`-only substring match
misses the capacity/unsupported/invalid-parameter failures, which are equally
strong "probing what I can launch" evidence.

**Error strings:** EC2 CloudTrail errors carry a `Client.` prefix —
`Client.VcpuLimitExceeded`, not `VcpuLimitExceeded`. Match with `contains` and
confirm against a sample event.

**Containment ordering note:** kill the *relaunch mechanism* (Auto Scaling
group, EC2 fleet, spot request) before terminating instances. Terminating first
just triggers a replacement launch.

**MITRE note:** the manifest maps T1204.003 (*User Execution: Malicious
Image*), which is a poor fit — nothing here depends on a malicious image. The
real behaviour is T1496 (*Resource Hijacking*, Impact). Both tags are carried
on the rules; the mapping is inherited from the upstream catalogue.

**Severity:** manifest MEDIUM; IR view Medium–High, rising to High once mining
is confirmed or the launch is at scale.

**GuardDuty:** `CryptoCurrency:EC2/BitcoinTool.B` and siblings under
`CryptoCurrency:EC2/`.

**Files here:**
- `sigma_t1204_003.yml` — three documents: unusual-type launch (`high`),
  GuardDuty mining finding (`critical`), and capability probing (`medium`).
- `kql_t1204_003.kql` — single query covering launches and failed probes, with
  mining-capable vs cost-abuse verdicts separated.

Full response procedure is in `../PLAYBOOK.md`.
