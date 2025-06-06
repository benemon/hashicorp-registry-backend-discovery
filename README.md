# HashiCorp Registry Backend Discovery

Daily monitoring and discovery of HashiCorp's container registry backend infrastructure, specifically tracking S3 endpoints and container image distribution for Terraform Enterprise.

## 🎯 Purpose

This tool monitors the backend infrastructure of HashiCorp's container registry to:

- **Track S3 endpoints** used for container layer storage
- **Monitor infrastructure changes** that might affect enterprise deployments
- **Provide visibility** into HashiCorp's container distribution architecture
- **Alert on changes** that could impact network allowlists or security policies

## 🚀 Features

### Automated Monitoring
- **Daily scans** at 6 AM UTC via GitHub Actions
- **Change detection** by comparing with previous scan results
- **Automatic alerting** via GitHub Issues when changes are detected
- **Persistent storage** using GitHub Actions cache for comparison

### Public Dashboard
- **GitHub Pages site** with real-time data visualization
- **Responsive design** that works on desktop and mobile
- **Clean data presentation** showing registry metadata and S3 endpoints
- **Auto-updating** from latest scan results

### Comprehensive Discovery
- **Container manifest analysis** for multiple Terraform Enterprise versions
- **Platform detection** (linux/amd64, etc.)
- **S3 endpoint enumeration** for each container layer
- **JSON output** for programmatic consumption

## 📊 Live Dashboard

View the latest discovery results at: **[GitHub Pages Site](https://[your-username].github.io/hashicorp-registry-backend-discovery/)**

The dashboard displays:
- Repository and registry information
- S3 endpoint summary
- Detailed container tag information
- Manifest metadata and platform support

## 🔧 How It Works

### Discovery Process
1. **Authenticates** with HashiCorp's container registry
2. **Enumerates** available Terraform Enterprise container tags
3. **Downloads manifests** for each tag version
4. **Extracts S3 endpoints** from layer blob URLs
5. **Generates comprehensive report** in JSON format

### Monitoring Workflow
1. **Restores** previous scan results from cache
2. **Runs** new discovery scan
3. **Compares** results with previous data
4. **Creates alerts** if infrastructure changes detected
5. **Updates** GitHub Pages dashboard
6. **Saves** current results for next comparison

## 🛠️ Setup

### Prerequisites
- GitHub repository with Actions enabled
- HashiCorp registry credentials
- GitHub Pages enabled (optional, for dashboard)

### Required Secrets
Configure these in your repository settings under Secrets and Variables > Actions:

```
REGISTRY_USERNAME - Your HashiCorp registry username
REGISTRY_PASSWORD - Your HashiCorp registry password/token
```

### Workflow Configuration
The monitoring runs automatically via GitHub Actions:
- **Schedule**: Daily at 6 AM UTC
- **Manual trigger**: Available via workflow_dispatch
- **Permissions**: Requires `contents: write` and `issues: write`

### GitHub Pages Setup (Optional)
1. Enable GitHub Pages in repository settings
2. Set source to "Deploy from a branch"
3. Choose `main` branch and `/docs` folder
4. Copy `docs/index.html` from this repository

## 📁 Repository Structure

```
├── .github/
│   ├── workflows/
│   │   └── backend-monitor.yml     # Main monitoring workflow
│   └── scripts/
│       └── compare_results.py      # Result comparison logic
├── docs/
│   ├── index.html                  # GitHub Pages dashboard
│   └── current-scan.json          # Latest scan data (auto-updated)
├── registry_backend_discovery.py  # Main discovery script
└── README.md                       # This file
```

## 🔍 Output Format

The discovery script generates JSON output with:

```json
{
  "repository": "hashicorp/terraform-enterprise",
  "registry": "https://images.releases.hashicorp.com",
  "discovery_timestamp": "2025-06-06 20:09:12 UTC",
  "tags": {
    "v202505-1": {
      "manifest_info": { ... },
      "platforms": [ ... ],
      "s3_endpoints": [ ... ]
    }
  },
  "summary": {
    "s3_endpoint_count": 1,
    "s3_endpoints": [ ... ]
  }
}
```

## 🚨 Alerting

When infrastructure changes are detected, the system automatically:

1. **Creates a GitHub Issue** with detailed change report
2. **Includes comparison details** showing what changed
3. **Provides context** about potential impact
4. **Suggests actions** for response
5. **Labels appropriately** for filtering and organization

## 🔧 Local Usage

Run the discovery script locally:

```bash
# Install dependencies
pip install requests

# Run discovery
python3 registry_backend_discovery.py \
  --username YOUR_USERNAME \
  --password YOUR_PASSWORD \
  --output json
```

## 📈 Use Cases

### Enterprise Operations
- **Network allowlisting**: Know which S3 endpoints to allow in corporate firewalls
- **Change management**: Get notified when HashiCorp updates their infrastructure
- **Compliance**: Track data residency by monitoring S3 endpoint regions

### Security Monitoring
- **Supply chain visibility**: Monitor container distribution infrastructure
- **Infrastructure tracking**: Understand the backend systems serving your containers
- **Change detection**: Alert on unexpected infrastructure modifications

### DevOps Planning
- **Deployment preparation**: Ensure network access to required endpoints
- **Incident response**: Quickly identify if issues are related to backend changes
- **Documentation**: Maintain current understanding of HashiCorp's infrastructure

## ⚠️ Important Notes

- **Monitoring scope**: Currently focused on Terraform Enterprise containers
- **Rate limiting**: Designed to be respectful of HashiCorp's infrastructure
- **Authentication required**: Valid HashiCorp registry credentials needed
- **No guarantee**: This is an unofficial monitoring tool; infrastructure may change

## 🤝 Contributing

Contributions welcome! Areas for improvement:

- Additional container repositories
- Enhanced change detection logic
- Improved dashboard visualizations
- Better error handling and retry logic
- Extended S3 endpoint analysis

## 📄 License

This project is provided as-is for infrastructure monitoring purposes. Please respect HashiCorp's terms of service when using their registry APIs.

---

**Note**: This is an unofficial monitoring tool. For official HashiCorp infrastructure information, please consult HashiCorp's documentation and support channels.
