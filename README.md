# Kybu — Zero-Touch AWS IAM Policy Generator

> **New to AWS or IAM?** No problem. This guide walks you through everything step by step.

Kybu is a small tool that runs on your computer and **watches your AWS commands in real-time** — then automatically builds a secure IAM policy based on exactly what you used. No guessing, no copy-pasting from Stack Overflow.

---

## What problem does this solve?

When working with AWS, you need an **IAM policy** to control what actions are allowed. Most people either:

- Grant way too many permissions (a security risk), or
- Spend hours manually figuring out the exact permissions needed

**Kybu fixes this.** Just run your AWS commands like you normally would, and Kybu builds the policy for you — automatically and securely.

---

## Features at a glance

| Feature                        | What it means for you                                                                                                    |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------ |
| **Zero-Touch Setup**           | Kybu configures itself on start and cleans up when you exit. No manual file editing.                                     |
| **Real-Time Dashboard**        | Open your browser to watch your policy being built live as you run commands.                                             |
| **Least Privilege by default** | Kybu targets the _exact_ resources you used (specific S3 buckets, DynamoDB tables, etc.) instead of using `*` wildcards. |
| **Works everywhere**           | Compatible with the AWS CLI, Python (boto3), JavaScript, Go SDKs, and more.                                              |
| **100% Local**                 | Nothing leaves your machine. No accounts, no sign-ups, no telemetry to external servers.                                 |

---

## Installation

### Step 1 — Download the binary

Go to the **[Releases page](https://github.com/InspectorGadget/kybu/releases)** and download the file that matches your operating system:

| Your OS                     | File to download         |
| --------------------------- | ------------------------ |
| macOS (Apple Silicon / M1+) | `kybu-darwin-arm64`      |
| macOS (Intel)               | `kybu-darwin-amd64`      |
| Linux (x86_64)              | `kybu-linux-amd64`       |
| Linux (ARM)                 | `kybu-linux-arm64`       |
| Windows (x86_64)            | `kybu-windows-amd64.exe` |
| Windows (ARM)               | `kybu-windows-arm64.exe` |

> **Not sure which to pick?** Most modern Macs use Apple Silicon (`arm64`). Most Windows/Linux PCs use `amd64`. If unsure, check: Apple menu → About This Mac (Mac) or Settings → System → About (Windows).

---

### Step 2 — Install it (so you can run it from anywhere)

#### **Option A: Homebrew (Recommended for macOS)**

The easiest way to install Kybu on macOS. This builds the tool from source on your machine, which **automatically bypasses macOS security warnings.**

```bash
# 1. Add our tap
brew tap InspectorGadget/tap

# 2. Install Kybu
brew install kybu

# 3. (Optional) To update in the future:
brew update
brew upgrade kybu
```

#### **Option B: Manual Install (MacOS/Linux)**

1. Open your terminal and navigate to the folder where you downloaded the file.
2. Run the following commands (replace `kybu-darwin-arm64` with your actual filename):

```bash
mv kybu-darwin-arm64 /usr/local/bin/kybu
chmod +x /usr/local/bin/kybu
```

> **What does this do?** `mv` renames the file to `kybu` and moves it to a folder your terminal already knows about. `chmod +x` makes it executable. After this, you can type `kybu` from any folder.

**Windows:**

1. Rename the downloaded file (e.g. `kybu-windows-amd64.exe`) to `kybu.exe`
2. Move `kybu.exe` to a folder like `C:\Tools\`
3. Add that folder to your **PATH** — [here's how](https://www.howtogeek.com/118594/how-to-edit-your-system-path-for-easy-command-line-access/)

---

## How to use Kybu

Kybu works by sitting in the background while you run your AWS commands. Here's the full flow:

### Step 1 — Start Kybu

```bash
kybu
```

> If you haven't added it to your PATH yet, you can run it directly from the folder you downloaded it to:
>
> ```bash
> # macOS/Linux (use your actual filename)
> ./kybu-darwin-arm64
>
> # Windows
> kybu-windows-amd64.exe
> ```

### Step 2 — Open the dashboard

Once Kybu is running, open your browser and go to:

```
http://localhost:8080
```

You'll see a live dashboard where your policy will appear.

### Step 3 — Run your AWS commands (in a new terminal window)

Open a **second terminal window** and run your AWS commands as you normally would. For example:

```bash
aws s3 ls s3://my-app-bucket
aws dynamodb describe-table --table-name UsersTable
```

Watch the dashboard — it logs every request and builds your policy in real time.

### Step 4 — Copy your policy

Once you're done, copy the JSON from the **"Policy Output"** panel in the dashboard, and paste it into the [AWS IAM Console](https://console.aws.amazon.com/iam/).

### Step 5 — Stop Kybu

Press `Ctrl+C` in the terminal where Kybu is running. It will automatically restore your AWS config to its original state.

---

## ⚙️ Options

You can customize Kybu with the following flags:

| Flag         | Default | Description                           |
| ------------ | ------- | ------------------------------------- |
| `--web-port` | `8080`  | Change the port the dashboard runs on |

**Example:**

```bash
kybu --web-port 9090
```

---

## Security & Privacy

- **Nothing leaves your machine.** Kybu only reads local AWS telemetry — it never sends your credentials, command history, or generated policies anywhere.
- **Automatic cleanup.** When you stop Kybu with `Ctrl+C`, it immediately restores your `~/.aws/config` to exactly how it was before.
- **Always review before applying.** Kybu does its best to find specific resource ARNs, but if it can't determine the exact resource, it falls back to a wildcard (`*`). Always review the generated policy before applying it to a production environment.

---

## How it works (under the hood)

Kybu uses a built-in AWS feature called **Client Side Monitoring (CSM)**, which lets the AWS SDK report API calls to a local listener. Kybu temporarily enables this in your `~/.aws/config`, captures the data, extracts resource ARNs from the raw responses, and assembles it all into a valid IAM policy JSON.

---

## Contributing

Contributions are welcome!

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Commit your changes
4. Push and open a Pull Request

---

## FAQ

**Q: Do I need to be logged into AWS for this to work?**
Yes. Kybu listens to your existing AWS CLI session. Make sure you're authenticated (`aws configure` or an active SSO session).

**Q: Will this affect my existing AWS config permanently?**
No. Kybu saves your original config and restores it on exit.

**Q: What if I forget to stop Kybu properly?**
You can manually remove the `csm_enabled = true` line from `~/.aws/config` if needed.

**Q: Can I use this with AWS SSO / IAM Identity Center?**
Yes, as long as your CLI session is active and configured, Kybu will capture the traffic.
