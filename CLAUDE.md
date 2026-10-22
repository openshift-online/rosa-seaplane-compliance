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
