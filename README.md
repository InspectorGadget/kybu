# Kybu (CLI)

## Overview

"Fire a request. Catch the rebound. Forge the policy." Kybu is a specialized AWS IAM policy generator that builds permissions by listening to the "echo" of your failed requests.

Unlike standard tools that rely on static dictionary lookups, Kybu acts as a forensic detective. It listens to AWS Client Side Monitoring (CSM) telemetry and uses regex heuristics to scrape the exact missing Action and Resource ARN directly from AWS AccessDenied error messages.

Say hello to Kybu, your new best friend for crafting precise IAM policies!

## Features

1. **Real-Time Policy Forging**: Instantly converts live AWS AccessDenied errors into valid IAM JSON statements, turning your failed requests into actionable permissions.
2. **Forensic Error Analysis**: Uses advanced regex heuristics to scrape hidden IAM actions (like kms:GenerateDataKey) and specific Resource ARNs directly from exception messages, bypassing the limitations of standard telemetry.
3. **Zero-Touch Telemetry**: Listens to the native AWS Client Side Monitoring (CSM) stream over UDP. No complex HTTP proxies, no SSL certificates, and no latency overhead.
4. **Live Action Dashboard**: Features a dark-mode, real-time web UI that groups permissions by service, highlights denied requests instantly, and includes one-click policy copying and stream management.

---

## Installation

Kybu is distributed as a single binary with no dependencies.

1. Download the latest release from the [GitHub Releases](https://github.com/InspectorGadget/kybu/releases) page.
2. Make the binary executable:
   ```bash
   chmod +x kybu
   ```
3. Run the binary:
   ```bash
   ./kybu
   ```
   **OR**
   ```bash
   ./kybu --web-port 8080
   ```

---

## Usage & Flags

By default, the web dashboard runs on port `8080` and the UDP listener on port `31000`. You can customize these settings using the following flags:

- `--web-port`: Specify a custom port for the web dashboard (default: `8080`). The dashboard can be accessed at `http://localhost:<web-port>`.

---

## Workflow

Kybu is designed to seamlessly integrate into your existing AWS SDK workflows. Here's how to get started:

1. **Enable CSM**: Ensure that AWS Client Side Monitoring (CSM) is enabled globally in your AWS SDK configuration. Kybu will automatically toggle this setting for you on startup.
2. **Run Kybu**: Start the Kybu binary. It will listen
   for CSM telemetry on UDP port `31000` by default.
3. **Trigger AccessDenied Errors**: Use your application as usual. When an AWS SDK call fails due to insufficient permissions, Kybu will capture the AccessDenied error messages from the CSM telemetry.
4. **View the Dashboard**: Open your web browser and navigate to `http://localhost:<web-port>` to access the Kybu dashboard. Here, you can view the forged IAM policies in real-time, grouped by service.

### Step 1: Enable CSM Globally

Note: This automatically injects csm_enabled = true into your AWS config file.

```bash
./kybu
CSM Enabled globally in '~/.aws/config'
```

### Step 2: Access the Dashboard

Open your web browser and navigate to:

```
http://localhost:8080
```

Note: Please keep Kybu running in the background and the Dashboard open in your browser to continue capturing telemetry in real-time.

### Step 3: Generate Traffic

In a new terminal window, run your Terraform plan, AWS CLI command, or Python script. Do not set any CSM environment variables manually; Kybu has already handled this globally.

Example:

```bash
aws s3 ls s3://my-private-bucket
```

### Step 3: View Forged Policies

As your application runs and encounters AccessDenied errors, Kybu will capture the relevant telemetry and display the forged IAM policies in the dashboard. You can copy these policies directly from the UI for use in your IAM roles or policies.

You will see:

1. Red Log Entries: The specific failed calls.
2. Forged IAM Statements: The exact Action and Resource ARN needed to resolve the AccessDenied errors.
3. Grouped by Service: Permissions are organized by AWS service for easy navigation.
4. One-Click Copy: Easily copy the generated IAM policies for immediate use.

---

## Stopping Kybu

When you are finished, simply press Ctrl+C in the terminal running Kybu.
**Note**: Kybu will automatically remove the csm_enabled = true line from your ~/.aws/config file to return your system to its original state.

```bash
Shutting down... Removing CSM flags.
```

---

## Troubleshooting

- **My logs are empty**:
  - Ensure that your AWS SDK calls are indeed failing with AccessDenied errors. Kybu only captures telemetry related to failed requests.
  - Verify that CSM is enabled in your AWS SDK configuration. Kybu should have done this automatically, but double-check your ~/.aws/config file.
- **I see "Access Denied" in my terminal, but Kybu didn't catch it.**:
  - Some AWS services do not emit CSM telemetry for every failure type. But Kybu captures the vast majority of common services.
  - Ensure the tool is running before you execute the failing command.
- **The policy disappeared when I refreshed!**:
  - As of the latest version, Kybu holds the policy state in the backend memory. Your policy will survive a browser refresh. Use the "Clear Stream" button in the UI to reset the state.
