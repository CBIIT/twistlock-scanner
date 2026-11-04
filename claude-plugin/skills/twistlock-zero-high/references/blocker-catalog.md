# Blocker Catalog

Single source of truth for `blocker_code`. `NI` = NEEDS_INPUT (user can unblock), `HS` = HARD_STOP.

| Code | Raised by | Type | Meaning | user_action | resume_from |
|---|---|---|---|---|---|
| MODE_UNCLEAR | scan-target-resolver | NI | User did not choose ECR or local | Ask: "Should I scan an ECR registry image, or build/use a local Docker image?" | scan-target-resolver |
| ECR_REF_MISSING | scan-target-resolver | NI | MODE=ecr but no image ref | Ask for the ECR image ref (example: `123456789012.dkr.ecr.us-east-1.amazonaws.com/app:tag`) | scan-target-resolver |
| ECR_REF_INVALID | scan-target-resolver | NI | Ref is not a valid ECR reference | Ask for a corrected ref | scan-target-resolver |
| LOCAL_TAG_MISSING | scan-target-resolver | NI | MODE=local but no tag chosen | Ask for a local tag (propose `<repo>:twistlock-candidate`) | scan-target-resolver |
| BUILD_COMMAND_UNRESOLVED | build-command-resolver | NI | No build script and Dockerfile/context ambiguous | Ask which Dockerfile and context to use | build-command-resolver |
| PREFECT_API_URL_MISSING | prefect-auth-preflight | NI | No Prefect API URL known | Provide the Prefect Cloud API URL or `<account>/<workspace>` | prefect-auth-preflight |
| PREFECT_NOT_LOGGED_IN | prefect-auth-preflight | NI | No existing login and no `PREFECT_API_KEY` | Run `uv run prefect cloud login` yourself (browser), then confirm. Never paste secrets in chat | prefect-auth-preflight |
| PREFECT_WORKSPACE_UNKNOWN | prefect-auth-preflight | NI | Workspace slug unknown | Provide `<account>/<workspace>` | prefect-auth-preflight |
| PREFECT_CLI_UNAVAILABLE | prefect-deployment-preflight | NI | `uv`/Prefect missing | Approve installing `prefect==3.3.4` via `uv pip install --system` | prefect-deployment-preflight |
| JQ_UNAVAILABLE | prefect-deployment-preflight | NI | `jq` missing | Install `jq`, then confirm | prefect-deployment-preflight |
| PREFECT_DEPLOYMENT_NOT_FOUND | prefect-deployment-preflight | HS | `twistlock-scan/twistlock-scan` absent in workspace | none | none |
| TWISTLOCK_CREDS_MISSING | twistlock-credential-preflight | NI | Neither `TWISTLOCK_TOKEN` nor username+password found | Add credentials to a repo-local env file or shell env on your own machine (template in commands-local.md). Never paste in chat. Confirm when done | twistlock-credential-preflight |
| TWISTLOCK_CREDS_PARTIAL | twistlock-credential-preflight | NI | Only one of username/password set | Add the missing variable, then confirm | twistlock-credential-preflight |
| TWISTLOCK_AUTH_FAILED | twistlock-auth-preflight | NI | Console rejected credentials or is unreachable | Verify credentials and VPN, then confirm | twistlock-auth-preflight |
| TWISTCLI_NOT_FOUND | twistcli-preflight | NI | No `twistcli` located | Provide the native `twistcli` path or place it at `./twistcli` | twistcli-preflight |
| TWISTCLI_INCOMPATIBLE_BINARY | twistcli-preflight | NI | Binary does not match host OS/arch | Provide a host-native binary. Do not use a privileged scanner container | twistcli-preflight |
| DOCKER_DAEMON_UNAVAILABLE | docker-preflight | NI | Daemon unreachable or permission denied | Start Docker / grant access, then confirm | docker-preflight |
| BASE_IMAGE_PULL_FAILED | image-builder | NI | DNS/TLS failure pulling a base image | Check Docker context and VPN, then confirm | image-builder |
| PKG_TLS_FAILURE | image-builder | NI | Package manager TLS failure inside build | Route to tls-ca-remediator (orchestrator action, no user step) | tls-ca-remediator |
| CA_CERT_MISSING | tls-ca-remediator | NI | No trusted CA file available for build secret | Export the CA from your keychain to `.twistlock-runs/nci-ca.pem` or give a path, then confirm | tls-ca-remediator |
| ECR_IMAGE_ACCESS_DENIED | ecr-scanner | HS | Deployment cannot pull the ECR image | none | none |
| PREFECT_RUN_FAILED | ecr-scanner | NI | Prefect auth/workspace error during run | Re-login or correct workspace, then confirm | prefect-auth-preflight |
| TWISTLOCK_PERMISSION_DENIED | ecr-scanner, local-scanner | HS | 403 (for example `custom-compliance`) | none | none |
| NEW_ECR_IMAGE_REQUIRED | orchestrator (via fix flow) | NI | Source fixed; ECR needs rebuild/push | Provide the new ECR image ref, or choose local validation | scan-target-resolver |
| FIX_UNAVAILABLE | fix-planner | HS | Fixed version not available from distro/vendor | none | none |
| MAJOR_UPGRADE_REQUIRED | fix-planner | HS | Next fix needs an unsupported major runtime upgrade | none | none |
| TRANSPORT_SECURITY_WEAKENED | fix-reviewer | HS | Build only passes by weakening transport security | none | none |
| FINDING_PERSISTS | gate-evaluator | HS | Same Critical/High finding remains after two reasonable attempts | none | none |
