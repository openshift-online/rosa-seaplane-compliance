# ROSA Seaplane Compliance - Claude Instructions

## Rule: controls are certification-agnostic

This project's controls will be reused across multiple certifications
(FedRAMP Class C, Canadian Protected B/ITSG-33, others later), not just one.
Never bake a specific certification's vocabulary or IDs into a control
catalog or policy (`gemara/*/controls.yaml`, `policy.yaml`); keep those
framework-neutral.

Framework-specific identity (KSI IDs, NIST controls, ITSG-33 controls, etc.)
belongs only in `mappings/*.mapping.yaml`. Adding a certification should mean
adding a mapping file, never editing an existing control catalog, policy, or
evidence pipeline.

## Rule: Rego policies are source-neutral when they can be

Keep Rego policies (`opa/*/policy/*.rego`) neutral to the evidence source
(GitHub, GitLab, etc.). The source-specific gathering belongs in `evidence/*.sh`,
which normalizes into a canonical shape the policy evaluates; adding a source
should mean adding a collector, not a new policy.

When a policy cannot stay neutral and leaks a source's vocabulary, name the file
and package for that source (e.g. `github_default_branch_merge_review.rego`, package
`...github_default_branch_merge_review`) so the coupling is explicit.
