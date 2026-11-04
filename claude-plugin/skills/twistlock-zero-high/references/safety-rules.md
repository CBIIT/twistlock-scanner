# Safety Rules (apply to every agent)

- When the user asks for Twistlock/Prisma Cloud, use Twistlock/Prisma Cloud only. Never substitute Trivy, Snyk, Docker Scout, or another scanner for the gate.
- Never print, commit, or store secrets, passwords, or generated Twistlock tokens. Never write them to `_workspace/`.
- Never suppress, waive, downgrade, hide, or ignore scanner findings as a fix.
- Never assume a local build is possible. If the mode is not explicit, the user chooses ECR or local.
- Never claim success from Dockerfile inspection. Success requires a fresh Twistlock scan of the selected image.
- MODE=local: prefer the repo build script over an invented build command.
- MODE=ecr: do not run local `twistcli` against ECR as the primary path. Use the Prefect `twistlock-scan/twistlock-scan` deployment and base the decision on its watched result.
- MODE=ecr: do not edit the local repo before the first Prefect scan unless the user explicitly asks for source remediation first.
- Do not make broad product/runtime changes unless scan evidence requires it.
- Do not weaken package transport security (for example HTTPS -> HTTP repositories) unless the user explicitly accepts the risk.
- If VPN/TLS interception breaks package manager TLS, use a build-time secret CA only. Never bake enterprise CA files into the final image.
- Do not use a Linux `twistcli` binary on macOS. Do not switch to a privileged scanner container to work around a binary mismatch.
- Never revert unrelated user changes in the working tree.
