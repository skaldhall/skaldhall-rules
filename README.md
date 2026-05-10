# skaldhall-rules

Sigma rule bundles for [Bragi](https://github.com/skaldhall/bragi).

The Bragi operator pulls `rules.tgz` from this repo and uploads each rule
into OpenSearch Security Analytics as a custom rule. Detectors created
for each promoted `LogSourcePipeline` then attach the rules whose category
matches the pipeline's OCSF class.

This works alongside (not in place of) OpenSearch's pre-packaged Sigma
ruleset. Custom rules complement the pre-packaged ones for OCSF classes
where the upstream coverage is thin or doesn't fit dynamically-mapped
indices.

## Layout

```
rules/
  <category>/
    <rule-id>.yml    # one Sigma rule per file
scripts/
  build-bundle.sh    # tars rules/ into rules.tgz
  validate.sh        # checks every rule is valid YAML + has the required keys
rules.tgz            # generated bundle the operator fetches
```

## Categories

Pre-packaged ruleset categories Bragi already uses (rules in these dirs
*supplement* the ~290 upstream ones):

| Category | OCSF class(es) | Pipelines |
|---|---|---|
| `linux` | 1007 process | tetragon, falco, tracee, sysdig-oss, kubearmor, inspektor-gadget, linux-auditd, selinux |
| `network` | 4001 | antrea-flow, calico-flow, hubble-flow, hubble-policy, suricata-eve, zeek |
| `others_web` | 4002 HTTP | haproxy, traefik-access, nginx-ingress-access, istio-envoy-access, kuma-dp, linkerd-proxy |
| `dns` | 4003 | calico-dns |
| `cloudtrail` | 6003 K8s API audit | etcd-audit, kube-apiserver-audit, kyverno-admission, vault-audit, harbor-audit, etcd-access, kubewarden-audit |

Custom Bragi categories — for OCSF classes the pre-packaged set doesn't
cover well:

| Category | OCSF class | Pipelines |
|---|---|---|
| `bragi-process` | 1007 (extends `linux`) | container-context rules layered on top |
| `bragi-network` | 4001 (extends `network`) | rules tuned for Cilium/Antrea/Calico flow shapes |
| `bragi-finding` | 2004 Detection Finding | falco, crowdsec, gatekeeper, kyverno, jspolicy, stackrox, coraza, cosign-verify, trivy-exposedsecret |
| `bragi-vuln` | 2002 Vulnerability Finding | trivy-vulnerabilityreport, kubehunter |
| `bragi-compliance` | 2006 Compliance Finding | kubebench, polaris-finding, trivy-configaudit |
| `bragi-iam` | 3005 User Access Mgmt | envoy-rbac, istio-authzpolicy-deny |
| `bragi-lifecycle` | 6002 Application Lifecycle | certmanager, kube-controller-manager, kube-scheduler, sealedsecrets, tekton-chains |
| `bragi-datastore` | 6008 Datastore Activity | kube-apiserver-server, kubelet, journald, calico-felix, nginx-ingress-error, pixie |
| `bragi-remediation` | 7001 Remediation Activity | externalsecrets-event, kube-events |
| `bragi-policy` | 1001 File System Activity (AppArmor enforcement) | apparmor |

## Authoring rules

Each file is a single Sigma rule. The `id` must be a UUID and unique
across the bundle. Required keys: `title`, `id`, `status`, `description`,
`logsource`, `detection`, `level`. Field references use OCSF v1.5 paths
(see [Bragi's registry SCHEMA.md](https://github.com/skaldhall/skaldhall-registry/blob/main/SCHEMA.md)).

### Example: tetragon shell-in-container

```yaml
title: Shell spawned inside a container
id: 8a8d3a82-1c9c-4e4a-a93b-3a5e3d6e6c66
status: experimental
description: A shell binary was exec'd inside a Kubernetes container.
references:
  - https://schema.ocsf.io/1.5.0/classes/process_activity
logsource:
  product: tetragon
  category: process_creation
detection:
  selection:
    process.cmd_line|contains:
      - '/bin/sh'
      - '/bin/bash'
      - '/bin/ash'
    kubernetes.container_name|exists: true
  condition: selection
level: medium
tags:
  - attack.execution
  - attack.t1059
```

## Build + validate

```bash
bash scripts/validate.sh
bash scripts/build-bundle.sh
```

`build-bundle.sh` writes `rules.tgz` at the repo root.

## License

(TBD before public release.)
