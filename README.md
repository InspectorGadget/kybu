# Kybu — Zero-Touch AWS IAM Policy Generator

Kybu watches your AWS commands and automatically builds a least-privilege IAM policy from your actual usage. No guessing, no wildcards.

---

## How it works

1. Kybu enables [Client Side Monitoring](https://docs.aws.amazon.com/sdkref/latest/guide/feature-csm.html) locally in `~/.aws/config`
2. You run your AWS commands as normal
3. Kybu captures every API call, scrapes the exact resource ARNs, and assembles a valid IAM policy
4. On exit (`Ctrl+C`), it restores your config to its original state

---

## Installation

### macOS — Homebrew (recommended)

```bash
brew tap InspectorGadget/tap
brew install kybu
```

### macOS / Linux — Manual

Download the correct binary from the **[Releases page](https://github.com/InspectorGadget/kybu/releases)**:

| OS                    | File                |
| --------------------- | ------------------- |
| macOS (Apple Silicon) | `kybu-darwin-arm64` |
| macOS (Intel)         | `kybu-darwin-amd64` |
| Linux (x86_64)        | `kybu-linux-amd64`  |
| Linux (ARM)           | `kybu-linux-arm64`  |

Then move it into your PATH:

```bash
# Replace the filename with whichever you downloaded
mv kybu-darwin-arm64 /usr/local/bin/kybu
chmod +x /usr/local/bin/kybu
```

### Windows

Download `kybu-windows-amd64.exe` or `kybu-windows-arm64.exe`, rename it to `kybu.exe`, and [add it to your PATH](https://www.howtogeek.com/118594/how-to-edit-your-system-path-for-easy-command-line-access/).

---

## Usage

**Terminal 1** — start Kybu:

```bash
kybu
```

**Browser** — open the live dashboard:

```
http://localhost:8080
```

**Terminal 2** — run your AWS commands:

```bash
aws s3 ls s3://my-app-bucket
aws dynamodb describe-table --table-name UsersTable
```

Watch the dashboard build your policy in real time. When done, copy the JSON from the **Policy Output** panel and paste it into the [AWS IAM Console](https://console.aws.amazon.com/iam/). Press `Ctrl+C` to stop Kybu.

---

## Options

| Flag         | Default | Description            |
| ------------ | ------- | ---------------------- |
| `--web-port` | `8080`  | Port for the dashboard |
| `--version`  | —       | Show current version   |

---

## Security & Privacy

- **Fully local.** No credentials, policies, or metadata are ever sent externally.
- **Auto-cleanup.** `~/.aws/config` is restored exactly as it was on exit.
- **Always review before applying.** If Kybu can't determine a specific resource ARN, it falls back to `*`. Treat generated policies as a starting point, not a final answer.

---

## FAQ

**Do I need to be authenticated with AWS?**
Yes — Kybu captures traffic from your active CLI session (`aws configure` or SSO).

**What if Kybu exits without cleaning up?**
Manually remove `csm_enabled = true` from `~/.aws/config`.

**Does it work with AWS SSO / IAM Identity Center?**
Yes, as long as your session is active.

---

## Contributing

1. Fork the repo
2. Create a branch: `git checkout -b feature/my-feature`
3. Commit, push, and open a Pull Request
