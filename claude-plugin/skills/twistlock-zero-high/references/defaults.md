# Organization Defaults (NCI)

Edit this file to retarget the harness at another organization. No agent hard-codes these values.

- Twistlock Console URL: `https://twistlock.nci.nih.gov` (use only when repo/user context clearly uses NCI Twistlock)
- Prefect Cloud API URL (NCI workspace):
  `https://api.prefect.cloud/api/accounts/90cb3bf5-1af1-44fa-8a6d-a1f111368e02/workspaces/5dd67daa-115c-40e2-92ad-8d6776766257`
- Prefect deployment: `twistlock-scan/twistlock-scan`
- Prefect CLI fallback install: `uv pip install --system "prefect==3.3.4"`
- Known native twistcli location (macOS): `<twistlock-scanner clone>/twistcli`
- Env file search order: `.env`, `backend/.env`, `deploy/.env`, `scripts/.env`
- Default local tag (only after the user chose local mode): `<repo-name>:twistlock-candidate`
- Build-time CA file location: `.twistlock-runs/nci-ca.pem` (override with `NCI_CA_CERT`)
