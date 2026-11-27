# KSI backlog

The in-phase KSIs that have no checks yet, and what is known about building each. To build one, follow [adding-a-ksi.md](adding-a-ksi.md).

**How this list was produced.** KSI names, statements and related-control counts come from the vendored FedRAMP dataset (`mappings/vendor/fedramp/fedramp-consolidated-rules.json`, through `scripts/fedramp_data.py`); the buckets from `mappings/fedramp-20x/ksi-scope.yaml`; "built" from the KSI records and `make coverage`; Prowler's candidate checks from its own FedRAMP 20x mapping (`<prowler-venv>/lib/python3.12/site-packages/prowler/compliance/fedramp_20x_ksi_2026.json`, Prowler 5.52.0). **Every data source below is unverified** (marked `[unverified]`) until someone checks it against the real systems; they are educated guesses from what the platform is, not findings. **Counts will drift as KSIs are built**: `make coverage` is the live view. No GitHub issues have been created from this list.

**Prowler candidates are candidates, not proof.** Each check is Prowler's own guess at what relates to a KSI. Before relying on one, read what it measures against what the KSI needs, and record why in `config/prowler/checks.yaml` (see "The Prowler rule" in the playbook). List a KSI's full AWS candidates with `jq -r '.requirements[]|select(.id=="KSI-XXX-YYY")|.checks.aws[]' <that file>`.

## Where we are

Built: `KSI-CMT-VTD`, `KSI-CMT-LMC`, `KSI-IAM-SNU`. Remaining: **32** (23 automatable, 9 hybrid) of the 35 in-phase KSIs.

| Family | Remaining automatable | Remaining hybrid | Remaining total |
| :-- | --: | --: | --: |
| CMT (Change Management) | 1 | 0 | 1 |
| CNA (Cloud Native Architecture) | 7 | 1 | 8 |
| IAM (Identity and Access Management) | 4 | 1 | 5 |
| MLA (Monitoring, Logging and Auditing) | 4 | 1 | 5 |
| PIY (Policy and Inventory) | 1 | 0 | 1 |
| RPL (Recovery Planning) | 0 | 2 | 2 |
| SCR (Supply Chain Risk) | 1 | 1 | 2 |
| SVC (Service Configuration) | 5 | 3 | 8 |
| **Total** | **23** | **9** | **32** |

## Suggested order of work (a suggestion, not a plan)

Ordered by effort against value; reorder freely. All of it needs the usual care: two methods of different kinds per KSI, and a person reading what each Prowler check measures.

1. **Reuse what already exists** (cheap, and each proves the pattern again): `KSI-IAM-AAM` (the credential report evidence is already collected), `KSI-SVC-ACM` and `KSI-CMT-RMV` (Argo CD state is readable through the metrics API we verified; the signed-query helper `evidence/lib/sigv4.py` and the client in `evidence/lib/argocd_health.py` already exist and can be reused), `KSI-MLA-ALA`, `KSI-PIY-GIV`.
2. **Configuration KSIs where Prowler has many candidates** (high value, but a big list to read and choose from, so budget the reading): `KSI-SVC-SIN`, `KSI-CNA-RNT`, `KSI-CNA-ULN`, `KSI-CNA-MAT`, `KSI-CNA-DFP`, `KSI-CNA-OFA`, `KSI-SVC-ASM`.
3. **Monitoring and supply chain**: `KSI-MLA-OSM`, `KSI-MLA-LET`, `KSI-MLA-EVC`, `KSI-SCR-MON`, `KSI-SVC-VRI`, `KSI-CNA-EIS`, `KSI-CNA-IBP`.
4. **Hard or dependent on things we do not have**: `KSI-IAM-ELP` and `KSI-IAM-JIT` (50+ related controls each and real permission analysis), `KSI-IAM-APM` (the identity provider is outside AWS), `KSI-SVC-VCM` (probably needs cluster-side access).
5. **Hybrids last**: start with the machine-checkable part of each and accept that the human part stays a process; `KSI-SVC-RUD` and `KSI-MLA-RVL` are almost entirely human.

## CMT: Change Management

### KSI-CMT-RMV: Redeploying vs Modifying

> Changes to machine-based information resources are executed through the redeployment of version controlled resources rather than direct modification wherever reasonable.

- **Bucket:** automatable. **Related controls:** 7.
- **Likely data sources [unverified]:** Terraform and the Argo CD application definitions in the platform repo (is deployment only through them?); CloudTrail write events by principals other than the pipelines; Argo CD out-of-sync state through the metrics API (reachable with the read-only role).
- **Prowler candidates (AWS), 2:** `autoscaling_group_using_ec2_launch_template`, `ecs_task_definitions_containers_readonly_access`. Prowler also lists 3 Kubernetes checks, which would need cluster access.

## CNA: Cloud Native Architecture

### KSI-CNA-DFP: Defining Functionality and Privileges

> The functionality and privileges for infrastructure and services are strictly defined.

- **Bucket:** automatable. **Related controls:** 5.
- **Likely data sources [unverified]:** AWS APIs and Terraform for task definitions, instance metadata settings and role policies; Prowler checks.
- **Prowler candidates (AWS), 6:** `ec2_instance_imdsv2_enabled`, `ecs_task_definitions_host_namespace_not_shared`, `ecs_task_definitions_host_networking_mode_users`, `ecs_task_definitions_no_privileged_containers`, `organizations_scp_check_deny_regions`, `sagemaker_notebook_instance_root_access_disabled`. Prowler also lists 7 Kubernetes checks, which would need cluster access.

### KSI-CNA-EIS: Enforcing Intended State

> Automated services are used to persistently assess the security of all machine-based information resources and automatically enforce their intended operational state.

- **Bucket:** automatable. **Related controls:** 12.
- **Likely data sources [unverified]:** Argo CD application settings (automated sync, self-heal) from the platform repo and sync state from the metrics API; AWS Config / Security Hub presence is NOT defined in the platform Terraform as far as we know, so confirm it exists at the organization level before depending on it.
- **Prowler candidates (AWS), 4:** `config_delegated_admin_and_org_aggregator_all_regions`, `config_recorder_all_regions_enabled`, `securityhub_enabled`, `ssm_managed_compliant_patching`.

### KSI-CNA-IBP: Implementing Best Practices

> The use and configuration of third-party machine-based information resources is persistently compared against the original provider's best practices and guidance.

- **Bucket:** automatable. **Related controls:** 4.
- **Likely data sources [unverified]:** A comparison against the provider's own best-practice benchmarks (for example a CIS-style Prowler framework run); Kubernetes benchmark tooling would need cluster access we do not have.
- **Prowler candidates (AWS), 9:** `awslambda_function_using_supported_runtimes`, `ec2_instance_with_outdated_ami`, `ecs_service_fargate_latest_platform_version`, `eks_cluster_uses_a_supported_version`, `kafka_cluster_uses_latest_version`, `opensearch_service_domains_updated_to_the_latest_service_software_version`, `rds_instance_deprecated_engine_version`, `wellarchitected_workload_no_high_or_medium_risks` (+1 more).

### KSI-CNA-MAT: Minimizing Attack Surface

> Machine-based information resources are persistently reviewed to ensure they have a minimal attack surface and that lateral movement is minimized if compromised.

- **Bucket:** automatable. **Related controls:** 15.
- **Likely data sources [unverified]:** AWS APIs: security groups, public addresses and endpoints, EKS endpoint access; Terraform; many Prowler checks.
- **Prowler candidates (AWS), 35:** `apigateway_restapi_public`, `appstream_fleet_default_internet_access_disabled`, `autoscaling_group_launch_configuration_no_public_ip`, `awslambda_function_not_publicly_accessible`, `awslambda_function_url_public`, `codebuild_project_not_publicly_accessible`, `dms_instance_no_public_access`, `ec2_instance_internet_facing_with_instance_profile` (+27 more). Prowler also lists 14 Kubernetes checks, which would need cluster access.

### KSI-CNA-OFA: Optimizing for Availability

> Machine-based information resources are persistently reviewed to ensure they are appropriately optimized for high availability and rapid recovery.

- **Bucket:** automatable. **Related controls:** 2.
- **Likely data sources [unverified]:** AWS APIs and Terraform: multi-AZ, autoscaling, backups and replication; many Prowler checks.
- **Prowler candidates (AWS), 37:** `autoscaling_group_capacity_rebalance_enabled`, `autoscaling_group_elb_health_check_enabled`, `autoscaling_group_multiple_az`, `autoscaling_group_multiple_instance_types`, `awslambda_function_vpc_multi_az`, `cloudfront_distributions_multiple_origin_failover_configured`, `directconnect_connection_redundancy`, `directconnect_virtual_interface_redundancy` (+29 more). Prowler also lists 2 Kubernetes checks, which would need cluster access.

### KSI-CNA-RNT: Restricting Network Traffic

> Machine-based information resources are persistently reviewed to ensure they are appropriately configured to limit inbound and outbound network traffic.

- **Bucket:** automatable. **Related controls:** 13.
- **Likely data sources [unverified]:** AWS APIs: security groups, network ACLs, route tables, VPC endpoints, egress rules.
- **Prowler candidates (AWS), 11:** `ec2_networkacl_allow_ingress_any_port`, `ec2_networkacl_allow_ingress_tcp_port_22`, `ec2_networkacl_allow_ingress_tcp_port_3389`, `ec2_securitygroup_allow_ingress_from_internet_to_all_ports`, `ec2_securitygroup_allow_ingress_from_internet_to_any_port`, `ec2_securitygroup_allow_ingress_from_internet_to_any_port_from_ip`, `ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports`, `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22` (+3 more). Prowler also lists 5 Kubernetes checks, which would need cluster access.

### KSI-CNA-ULN: Using Logical Networking

> Logical networking and related capabilities are used and persistently reviewed to enforce traffic flow controls.

- **Bucket:** automatable. **Related controls:** 12.
- **Likely data sources [unverified]:** AWS APIs: VPCs, subnets, flow logs, segmentation between accounts.
- **Prowler candidates (AWS), 9:** `eks_cluster_network_policy_enabled`, `eks_cluster_vpc_cni_network_policy_enforced`, `networkfirewall_in_all_vpc`, `networkfirewall_policy_default_action_fragmented_packets`, `networkfirewall_policy_default_action_full_packets`, `networkfirewall_policy_rule_group_associated`, `vpc_endpoint_connections_trust_boundaries`, `vpc_endpoint_services_allowed_principals_trust_boundaries` (+1 more).

### KSI-CNA-RVP: Reviewing Protections

> The effectiveness of protection against denial of service attacks and other unwanted activity for machine-based information resources is persistently reviewed.

- **Bucket:** hybrid. **Related controls:** 5.
- **Machine-checkable part, and likely data sources [unverified]:** Presence and configuration of denial-of-service protections (WAF, rate limiting, shield, load-balancer settings) and alarms.
- **Prowler candidates (AWS), 21:** `apigateway_restapi_waf_acl_attached`, `cloudfront_distributions_using_waf`, `cognito_user_pool_waf_acl_attached`, `elb_desync_mitigation_mode`, `elbv2_desync_mitigation_mode`, `elbv2_waf_acl_attached`, `fms_policy_compliant`, `shield_advanced_protection_in_associated_elastic_ips` (+13 more). Prowler also lists 5 Kubernetes checks, which would need cluster access.
- **Human judgment (not automatable):** A person reviews whether the protections are effective, on a schedule, and records it.

## IAM: Identity and Access Management

### KSI-IAM-AAM: Automating Account Management

> The lifecycle and privileges of all accounts, roles, and groups are securely managed using automation.

- **Bucket:** automatable. **Related controls:** 10.
- **Likely data sources [unverified]:** The IAM credential report and key inventory we already collect for KSI-IAM-SNU (reuse the evidence shape); unused credentials; root user keys; account lifecycle automation in Terraform and the SAML role setup.
- **Prowler candidates (AWS), 6:** `iam_no_root_access_key`, `iam_root_credentials_management_enabled`, `iam_user_accesskey_unused`, `iam_user_console_access_unused`, `iam_user_no_setup_initial_access_key`, `organizations_delegated_administrators`.

### KSI-IAM-APM: Adopting Passwordless Methods

> Secure passwordless methods are used for user authentication and authorization when feasible, otherwise strong passwords with phishing-resistant MFA is used.

- **Bucket:** automatable. **Related controls:** 17.
- **Likely data sources [unverified]:** User authentication happens at the identity provider (SAML/SSO), outside AWS, so the real evidence is probably IdP settings we cannot read today; from AWS only root and IAM-user MFA state.
- **Prowler candidates (AWS), 13:** `cognito_user_pool_password_policy_lowercase`, `cognito_user_pool_password_policy_minimum_length_14`, `cognito_user_pool_password_policy_number`, `cognito_user_pool_password_policy_symbol`, `cognito_user_pool_password_policy_uppercase`, `iam_password_policy_lowercase`, `iam_password_policy_minimum_length_14`, `iam_password_policy_number` (+5 more).

### KSI-IAM-ELP: Ensuring Least Privilege

> Identity and access management measures are used and persistently reviewed to ensure each user or device can only access the resources they need.

- **Bucket:** automatable. **Related controls:** 52.
- **Likely data sources [unverified]:** IAM policy analysis (wildcards, attached admin policies, privilege-escalation paths), IAM Access Analyzer unused-access findings, role trust policies. Large: 52 related controls and it needs real permission analysis.
- **Prowler candidates (AWS), 10:** `accessanalyzer_enabled`, `accessanalyzer_enabled_without_findings`, `bedrock_agent_role_least_privilege`, `bedrock_agent_role_not_shared_across_agents`, `efs_access_point_enforce_root_directory`, `efs_access_point_enforce_user_identity`, `iam_role_access_not_stale_to_bedrock`, `iam_user_access_not_stale_to_bedrock` (+2 more). Prowler also lists 10 Kubernetes checks, which would need cluster access.

### KSI-IAM-JIT: Authorizing Just-in-Time

> A least-privileged, role and attribute-based, and just-in-time security authorization model is used and persistently reviewed for all user and non-user accounts and services.

- **Bucket:** automatable. **Related controls:** 51.
- **Likely data sources [unverified]:** Federated, role-based access with short sessions and no standing admin: SAML role setup, role session durations, standing credentials. Large: 51 related controls.
- **Prowler candidates (AWS), 24:** `bedrock_api_key_no_administrative_privileges`, `bedrock_full_access_policy_attached`, `iam_aws_attached_policy_no_administrative_privileges`, `iam_customer_attached_policy_no_administrative_privileges`, `iam_customer_unattached_policy_no_administrative_privileges`, `iam_group_administrator_access_policy`, `iam_inline_policy_allows_privilege_escalation`, `iam_inline_policy_no_administrative_privileges` (+16 more).

### KSI-IAM-SUS: Responding to Suspicious Activity

> Accounts with privileged access are disabled or otherwise secured in response to suspicious activity.

- **Bucket:** hybrid. **Related controls:** 20.
- **Machine-checkable part, and likely data sources [unverified]:** Privileged-account inventory, MFA state, anomaly-detection services enabled (for example GuardDuty), the ability to disable an account.
- **Prowler candidates (AWS), 3:** `cognito_user_pool_advanced_security_enabled`, `cognito_user_pool_blocks_compromised_credentials_sign_in_attempts`, `cognito_user_pool_blocks_potential_malicious_sign_in_attempts`.
- **Human judgment (not automatable):** Deciding that activity is suspicious and acting on it, and the record that someone did.

## MLA: Monitoring, Logging and Auditing

### KSI-MLA-ALA: Authorizing Log Access

> A least-privileged, role and attribute-based, and just-in-time access authorization model is used and persistently reviewed for access to log data based on organizationally defined data sensitivity.

- **Bucket:** automatable. **Related controls:** 3.
- **Likely data sources [unverified]:** Bucket and log-group policies, cross-account sharing, who may read the audit logs (AWS APIs).
- **Prowler candidates (AWS), 4:** `cloudtrail_logs_s3_bucket_is_not_publicly_accessible`, `cloudwatch_cross_account_sharing_disabled`, `cloudwatch_log_group_not_publicly_accessible`, `iam_inline_policy_no_full_access_to_cloudtrail`.

### KSI-MLA-EVC: Evaluating Configurations

> The configuration of machine-based information resources, especially infrastructure as code, is persistently evaluated and tested.

- **Bucket:** automatable. **Related controls:** 7.
- **Likely data sources [unverified]:** Results of the infrastructure-as-code checks that run in CI on every change (the Prow validate, lint and rendered-files jobs) read through the GitHub status API or Prow; Config recorder state.
- **Prowler candidates (AWS), 1:** `config_recorder_all_regions_enabled`.

### KSI-MLA-LET: Logging Event Types

> A list of information resources and event types that will be logged, monitored, and audited is maintained and persistently reviewed to ensure these activities occur.

- **Bucket:** automatable. **Related controls:** 16.
- **Likely data sources [unverified]:** Which services log what: audit trail settings, flow logs, load balancer and storage access logs; plus a maintained list of event types (a document, so the human part is in a repo file). Many Prowler checks.
- **Prowler candidates (AWS), 43:** `apigateway_restapi_logging_enabled`, `apigatewayv2_api_access_logging_enabled`, `appsync_field_level_logging_enabled`, `athena_workgroup_logging_enabled`, `awslambda_function_invoke_api_operations_cloudtrail_logging_enabled`, `bedrock_model_invocation_logging_enabled`, `cloudfront_distributions_logging_enabled`, `cloudtrail_bedrock_logging_enabled` (+35 more). Prowler also lists 1 Kubernetes checks, which would need cluster access.

### KSI-MLA-OSM: Operating SIEM Capability

> A Security Information and Event Management (SIEM) or similar system(s) is used and persistently reviewed for centralized, tamper-resistant logging of events, activities, and changes.

- **Bucket:** automatable. **Related controls:** 22.
- **Likely data sources [unverified]:** Centralized, tamper-resistant logging: an organization trail delivering to a separate account, log file validation, bucket protections; whether a SIEM-like consumer exists is outside AWS configuration.
- **Prowler candidates (AWS), 7:** `cloudtrail_bucket_requires_mfa_delete`, `cloudtrail_cloudwatch_logging_enabled`, `cloudtrail_kms_encryption_enabled`, `cloudtrail_log_file_validation_enabled`, `cloudtrail_multi_region_enabled`, `cloudwatch_log_group_kms_encryption_enabled`, `cloudwatch_log_group_retention_policy_specific_days_enabled`. Prowler also lists 4 Kubernetes checks, which would need cluster access.

### KSI-MLA-RVL: Reviewing Logs

> Logs are persistently reviewed and audited.

- **Bucket:** hybrid. **Related controls:** 10.
- **Machine-checkable part, and likely data sources [unverified]:** Evidence that review happens: saved queries or scheduled reports exist, alert routing is configured, review tickets or records exist on a schedule.
- **Prowler candidates (AWS):** none in its mapping.
- **Human judgment (not automatable):** The review of the logs itself, and judging whether it was adequate.

## PIY: Policy and Inventory

### KSI-PIY-GIV: Generating Inventories

> Authoritative sources are used to automatically generate real-time inventories of all information resources when needed.

- **Bucket:** automatable. **Related controls:** 9.
- **Likely data sources [unverified]:** AWS Config recorder and aggregator, Resource Explorer indexes; the repo's own Terraform state as an inventory source.
- **Prowler candidates (AWS), 3:** `config_delegated_admin_and_org_aggregator_all_regions`, `config_recorder_all_regions_enabled`, `resourceexplorer2_indexes_found`.

## RPL: Recovery Planning

### KSI-RPL-ABO: Aligning Backups with Objectives

> The alignment of machine-based information resource backups with defined recovery objectives is persistently reviewed.

- **Bucket:** hybrid. **Related controls:** 5.
- **Machine-checkable part, and likely data sources [unverified]:** Backup plans, retention and point-in-time-recovery settings compared with the recorded recovery objectives (the objectives must be written down in a file we can read).
- **Prowler candidates (AWS), 17:** `dlm_ebs_snapshot_lifecycle_policy_exists`, `documentdb_cluster_backup_enabled`, `dynamodb_table_protected_by_backup_plan`, `dynamodb_tables_pitr_enabled`, `ec2_ebs_volume_protected_by_backup_plan`, `ec2_ebs_volume_snapshots_exists`, `efs_have_backup_enabled`, `elasticache_redis_cluster_backup_enabled` (+9 more).
- **Human judgment (not automatable):** Setting the recovery objectives and deciding they are still right.

### KSI-RPL-TRC: Testing Recovery Capabilities

> The capability to recover from incidents and contingencies aligned with defined recovery objectives is persistently tested.

- **Bucket:** hybrid. **Related controls:** 12.
- **Machine-checkable part, and likely data sources [unverified]:** Evidence that restore tests ran and succeeded: scheduled restore jobs or exercise records, DR job history.
- **Prowler candidates (AWS), 1:** `drs_job_exist`.
- **Human judgment (not automatable):** Designing the tests and judging whether recovery meets the objectives.

## SCR: Supply Chain Risk

### KSI-SCR-MON: Monitoring Supply Chain Risk

> Third party software information resources are automatically monitored for upstream vulnerabilities using mechanisms that may include contractual notification requirements or active monitoring services.

- **Bucket:** automatable. **Related controls:** 14.
- **Likely data sources [unverified]:** GitHub dependency-update and alert settings (Dependabot, Konflux or Renovate configs, alert APIs); registry scanning (ECR enhanced scanning, Inspector); runtime support status.
- **Prowler candidates (AWS), 6:** `awslambda_function_using_supported_runtimes`, `ecr_registry_enhanced_scanning_enabled`, `inspector2_active_findings_exist`, `inspector2_is_enabled`, `ssm_managed_compliant_patching`, `elasticbeanstalk_environment_php_platform_updated`.

### KSI-SCR-MIT: Mitigating Supply Chain Risk

> Potential supply chain risks are persistently identified, reviewed, and mitigated.

- **Bucket:** hybrid. **Related controls:** 31.
- **Machine-checkable part, and likely data sources [unverified]:** Dependency scanning and SBOM presence, signed images, time-to-fix for upstream vulnerabilities, supplier lists kept in the repo.
- **Prowler candidates (AWS), 10:** `awslambda_function_using_cross_account_layers`, `codeartifact_packages_external_public_publishing_disabled`, `codebuild_project_user_controlled_buildspec`, `codebuild_project_uses_allowed_github_organizations`, `ecr_registry_enhanced_scanning_enabled`, `ecr_registry_scan_images_on_push_enabled`, `ecr_repositories_not_publicly_accessible`, `ecr_repositories_scan_vulnerabilities_in_latest_image` (+2 more). Prowler also lists 1 Kubernetes checks, which would need cluster access.
- **Human judgment (not automatable):** Accepting, mitigating or rejecting a supply-chain risk.

## SVC: Service Configuration

### KSI-SVC-ACM: Automating Configuration Management

> The configuration of machine-based information resources is managed using automation and persistently reviewed for drift.

- **Bucket:** automatable. **Related controls:** 15.
- **Likely data sources [unverified]:** Drift: Argo CD out-of-sync state through the metrics API (reachable with the read-only role); Config recorder and SSM management state; Terraform plan drift in the pipelines.
- **Prowler candidates (AWS), 3:** `config_recorder_all_regions_enabled`, `ec2_instance_managed_by_ssm`, `ssm_managed_compliant_patching`.

### KSI-SVC-ASM: Automating Secret Management

> Management, protection, and regular rotation of digital keys, certificates, and other secrets is automated and persistently reviewed.

- **Bucket:** automatable. **Related controls:** 6.
- **Likely data sources [unverified]:** Secrets Manager rotation, KMS key rotation, certificate expiry and renewal; many Prowler checks.
- **Prowler candidates (AWS), 33:** `acm_certificates_expiration_check`, `amplify_app_no_secrets_in_environment`, `apigateway_restapi_no_secrets_in_stage_variables`, `awslambda_function_no_secrets_in_code`, `awslambda_function_no_secrets_in_variables`, `awslambda_layer_no_secrets_in_content`, `batch_job_definition_no_secrets`, `cloudformation_stack_outputs_find_secrets` (+25 more). Prowler also lists 5 Kubernetes checks, which would need cluster access.

### KSI-SVC-SIN: Securing Information

> Information is encrypted or otherwise secured from unwanted access or modification.

- **Bucket:** automatable. **Related controls:** 19.
- **Likely data sources [unverified]:** Encryption at rest and in transit across storage, databases, volumes, queues and listeners (AWS APIs); the largest Prowler candidate list, so choose deliberately.
- **Prowler candidates (AWS), 97:** `apigateway_restapi_cache_encrypted`, `athena_workgroup_encryption`, `awslambda_function_env_vars_not_encrypted_with_cmk`, `backup_recovery_point_encrypted`, `backup_vaults_encrypted`, `bedrock_custom_model_encrypted_with_cmk`, `bedrock_knowledge_base_encrypted_with_cmk`, `bedrock_prompt_encrypted_with_cmk` (+89 more). Prowler also lists 7 Kubernetes checks, which would need cluster access.

### KSI-SVC-VCM: Validating Communications

> The authenticity and integrity of communications between machine-based information resources is persistently validated using automation.

- **Bucket:** automatable. **Related controls:** 7.
- **Likely data sources [unverified]:** Whether service-to-service traffic is authenticated and integrity-protected (mutual TLS, signed requests, a service mesh); probably needs cluster-side information we do not have. Prowler's three candidates look like weak fits.
- **Prowler candidates (AWS), 3:** `apigateway_restapi_client_certificate_enabled`, `kafka_cluster_mutual_tls_authentication_enabled`, `ses_identity_dkim_enabled`. Prowler also lists 10 Kubernetes checks, which would need cluster access.

### KSI-SVC-VRI: Validating Resource Integrity

> Use cryptographic methods to validate the integrity of machine-based information resources.

- **Bucket:** automatable. **Related controls:** 14.
- **Likely data sources [unverified]:** Cryptographic integrity of artifacts: image signing and digest pinning (the build pipeline's enterprise-contract style checks), audit log file validation.
- **Prowler candidates (AWS), 7:** `cloudtrail_log_file_validation_enabled`, `kms_key_enclave_attestation_bypassable_path`, `kms_key_enclave_attestation_no_deployment_binding`, `kms_key_enclave_attestation_not_enforced`, `kms_key_enclave_attestation_pcr_mismatch`, `kms_key_enclave_attestation_unknown_image`, `kms_key_enclave_debug_attestation_detected`. Prowler also lists 4 Kubernetes checks, which would need cluster access.

### KSI-SVC-EIS: Evaluating and Improving Security

> Information resources are persistently evaluated for opportunities to improve security and those improvements are persistently made.

- **Bucket:** hybrid. **Related controls:** 12.
- **Machine-checkable part, and likely data sources [unverified]:** Backlog and trend of security findings (Trusted Advisor, scanners) and time to fix.
- **Prowler candidates (AWS), 1:** `trustedadvisor_errors_and_warnings`.
- **Human judgment (not automatable):** Choosing which improvements to make and recognizing that they were made.

### KSI-SVC-PRR: Preventing Residual Risk

> Plans, procedures, and the state of information resources are persistently reviewed after making changes to limit and remove unwanted residual elements that would likely negatively affect the confidentiality, integrity, or availability of federal customer data.

- **Bucket:** hybrid. **Related controls:** 5.
- **Machine-checkable part, and likely data sources [unverified]:** Dangling or unused resources after change: unassigned addresses, dangling DNS records, orphaned origins, leftover buckets.
- **Prowler candidates (AWS), 4:** `cloudfront_distributions_s3_origin_non_existent_bucket`, `ec2_elastic_ip_unassigned`, `lightsail_static_ip_unused`, `route53_dangling_ip_subdomain_takeover`.
- **Human judgment (not automatable):** Reviewing plans and procedures after changes.

### KSI-SVC-RUD: Removing Unwanted Data

> Unwanted federal customer data is removed promptly when requested by an agency in alignment with customer agreements, including from backups if appropriate; this typically applies when a customer spills information or when a customer seeks to remove information from a service due to a change in usage.

- **Bucket:** hybrid. **Related controls:** 5.
- **Machine-checkable part, and likely data sources [unverified]:** Very little: retention and expiry settings on backups and storage; the deletion workflow is a procedure.
- **Prowler candidates (AWS):** none in its mapping.
- **Human judgment (not automatable):** Almost all of it: deciding a request is valid, removing the data, and proving it from backups too.

## Deferred: the process KSIs

These 11 are about human processes. They are **deferred, not exempt**: Class C asks for at least two automated methods per KSI, while the SDR rules also allow stating that automation is not necessary for a measure, and the rules do not say which governs. The likely answer is to keep the review human and automate the proof that it happened.

- `KSI-CED-RAT`: Reviewing All Training
- `KSI-CMT-RVP`: Reviewing Change Procedures
- `KSI-INR-AAR`: Generating After Action Reports
- `KSI-INR-RIR`: Reviewing Incident Response Procedures
- `KSI-INR-RPI`: Reviewing Past Incidents
- `KSI-PIY-RES`: Reviewing Executive Support
- `KSI-PIY-RIS`: Reviewing Investments in Security
- `KSI-PIY-RSD`: Reviewing Security in the SDLC
- `KSI-PIY-RVD`: Reviewing Vulnerability Disclosures
- `KSI-RPL-ARP`: Aligning Recovery Plan
- `KSI-RPL-RRO`: Reviewing Recovery Objectives
