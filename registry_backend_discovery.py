#!/usr/bin/env python3
"""
HashiCorp Container Registry Provenance Discovery Tool

Analyzes HashiCorp's container registry to map the complete supply chain from 
registry manifests through to underlying S3 storage infrastructure. Provides 
factual data about image provenance without making security assessments.

Key Features:
- Registry manifest analysis and digest extraction
- Multi-architecture platform support (linux/amd64, etc.)
- Container layer → S3 storage endpoint mapping
- Authentication with HashiCorp's registry
- Multiple output formats (JSON, summary, detailed)

Use Cases:
- Supply chain analysis and documentation
- Infrastructure mapping for security assessments  
- Container image provenance research
- Registry backend discovery

Note: This tool provides raw data for analysis. Users should make their own
security assessments based on the factual information provided.
"""

import requests
import json
import re
from urllib.parse import urlparse
import sys
import time
import base64
import os
import hashlib
import subprocess

class HashiCorpProvenanceDiscovery:
    """
    Discovers and maps HashiCorp container registry infrastructure.
    
    This class provides methods to:
    - Authenticate with HashiCorp's container registry
    - Fetch and parse container image manifests
    - Trace container layers to underlying S3 storage
    - Map multi-architecture platform support
    - Extract provenance data without making security judgments
    
    The tool focuses on factual data collection rather than security validation,
    allowing users to make their own assessments based on the discovered information.
    """
    
    def __init__(self, debug=False):
        self.base_url = "https://images.releases.hashicorp.com"
        self.repo = "hashicorp/terraform-enterprise"
        self.s3_endpoints = set()
        self.blob_urls = set()
        self.session = requests.Session()
        self.auth_token = None
        self.debug = debug
        self.session.headers.update({
            'User-Agent': 'Docker/24.0.0',
            'Accept': 'application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json'
        })

    def log_debug(self, message):
        """Log debug message if debug mode is enabled."""
        if self.debug:
            print(f"DEBUG: {message}")

    def setup_authentication(self, username=None, password=None, token=None):
        """Setup authentication for the registry."""
        if token:
            self.auth_token = token
            self.session.headers['Authorization'] = f'Bearer {token}'
            return True
        
        if username and password:
            return self._authenticate_with_credentials(username, password)
        
        return self._get_docker_credentials()

    def _get_docker_credentials(self):
        """Try to get credentials from Docker config."""
        try:
            docker_config_path = os.path.expanduser('~/.docker/config.json')
            if os.path.exists(docker_config_path):
                with open(docker_config_path, 'r') as f:
                    config = json.load(f)
                
                auths = config.get('auths', {})
                registry_key = None
                
                possible_keys = [
                    'images.releases.hashicorp.com',
                    'https://images.releases.hashicorp.com',
                    'https://images.releases.hashicorp.com/v2/'
                ]
                
                for key in possible_keys:
                    if key in auths:
                        registry_key = key
                        break
                
                if registry_key and 'auth' in auths[registry_key]:
                    auth_str = base64.b64decode(auths[registry_key]['auth']).decode('utf-8')
                    username, password = auth_str.split(':', 1)
                    return self._authenticate_with_credentials(username, password)
        except Exception:
            pass
        
        return False

    def _authenticate_with_credentials(self, username, password):
        """Authenticate using username/password."""
        try:
            auth_url = f"{self.base_url}/v2/"
            response = self.session.get(auth_url, timeout=10)
            
            if response.status_code == 401:
                auth_header = response.headers.get('WWW-Authenticate', '')
                if 'Bearer' in auth_header:
                    realm_match = re.search(r'realm="([^"]+)"', auth_header)
                    service_match = re.search(r'service="([^"]+)"', auth_header)
                    
                    if realm_match:
                        realm = realm_match.group(1)
                        service = service_match.group(1) if service_match else 'registry'
                        
                        token_url = f"{realm}?service={service}&scope=repository:{self.repo}:pull"
                        token_response = requests.get(token_url, 
                                                    auth=(username, password), 
                                                    timeout=10)
                        
                        if token_response.status_code == 200:
                            token_data = token_response.json()
                            self.auth_token = token_data.get('token') or token_data.get('access_token')
                            if self.auth_token:
                                self.session.headers['Authorization'] = f'Bearer {self.auth_token}'
                                return True
            
            basic_auth = base64.b64encode(f"{username}:{password}".encode()).decode()
            self.session.headers['Authorization'] = f'Basic {basic_auth}'
            return True
            
        except Exception:
            return False

    def test_authentication(self):
        """Test if authentication is working."""
        try:
            url = f"{self.base_url}/v2/{self.repo}/tags/list"
            response = self.session.get(url, timeout=10)
            return response.status_code == 200
        except Exception:
            return False

    def calculate_manifest_digest(self, manifest_content):
        """Calculate the canonical digest of a manifest."""
        sha256_hash = hashlib.sha256(manifest_content).hexdigest()
        return f"sha256:{sha256_hash}"

    def extract_digest_from_headers(self, response):
        """Extract digest from response headers using multiple methods."""
        possible_digest_headers = [
            'Docker-Content-Digest',
            'Content-Digest',
            'Digest',
            'ETag'
        ]
        
        for header in possible_digest_headers:
            digest_value = response.headers.get(header)
            if digest_value:
                self.log_debug(f"Found digest candidate in {header}: {digest_value}")
                
                # Clean up ETag if needed
                if header == 'ETag':
                    digest_value = digest_value.strip('"').replace('W/', '')
                
                # Validate digest format
                if digest_value.startswith('sha256:') and len(digest_value) == 71:
                    self.log_debug(f"Valid digest found: {digest_value}")
                    return digest_value
        
        return None

    def fetch_manifest_with_digest_validation(self, tag):
        """Fetch manifest and return both manifest and digest info."""
        try:
            url = f"{self.base_url}/v2/{self.repo}/manifests/{tag}"
            
            # Try different Accept header strategies
            accept_strategies = [
                'application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.index.v1+json',
                'application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json'
            ]
            
            for i, accept_header in enumerate(accept_strategies, 1):
                headers = {'Accept': accept_header}
                response = self.session.get(url, headers=headers, timeout=15, allow_redirects=True)
                
                if response.status_code == 200:
                    self.log_debug(f"Manifest fetch successful with strategy {i}")
                    
                    # Extract digest from headers
                    header_digest = self.extract_digest_from_headers(response)
                    
                    # Calculate digest from content
                    calculated_digest = self.calculate_manifest_digest(response.content)
                    
                    # Parse manifest
                    manifest = response.json()
                    
                    digest_info = {
                        "authoritative_digest": header_digest or calculated_digest
                    }
                    
                    return manifest, digest_info
                
        except Exception as e:
            self.log_debug(f"Manifest fetch failed: {e}")
            
        return None, None

    def discover_comprehensive_provenance(self, num_tags=5):
        """Main discovery method with complete provenance tracking."""
        if not self.test_authentication():
            return {"error": "Authentication failed"}
        
        results = {
            "repository": self.repo,
            "registry": self.base_url,
            "discovery_timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "tags": {},
            "summary": {
                "s3_endpoint_count": 0,
                "s3_endpoints": []
            }
        }
        
        all_tags = self._get_available_tags()
        tags_to_analyze = all_tags[:num_tags] if all_tags else ['latest']
        
        for tag in tags_to_analyze:
            self.log_debug(f"Analyzing tag: {tag}")
            
            tag_data = {
                "manifest_info": {
                    "found": False,
                    "type": None,
                    "digest": None,
                    "size": 0
                },
                "platforms": [],
                "layers": [],
                "s3_endpoints": []
            }
            
            try:
                # Fetch and validate manifest
                manifest, digest_info = self.fetch_manifest_with_digest_validation(tag)
                
                if manifest and digest_info:
                    tag_data["manifest_info"]["found"] = True
                    tag_data["manifest_info"]["type"] = manifest.get("mediaType", "unknown")
                    tag_data["manifest_info"]["digest"] = digest_info["authoritative_digest"]
                    tag_data["manifest_info"]["size"] = len(json.dumps(manifest).encode('utf-8'))
                    
                    # Analyze manifest structure and blobs
                    analysis = self._analyze_manifest_for_provenance(manifest)
                    tag_data.update(analysis)
                    
            except Exception as e:
                tag_data["error"] = str(e)
                self.log_debug(f"Error analyzing tag {tag}: {e}")
            
            results["tags"][tag] = tag_data
        
        # Aggregate S3 endpoints
        all_s3_endpoints = set()
        for tag_data in results["tags"].values():
            all_s3_endpoints.update(tag_data.get("s3_endpoints", []))
        
        # Update summary
        unique_endpoints = sorted(list(all_s3_endpoints))
        results["summary"]["s3_endpoint_count"] = len(unique_endpoints)
        results["summary"]["s3_endpoints"] = unique_endpoints
        
        return results

    def _analyze_manifest_for_provenance(self, manifest):
        """Analyze manifest and extract factual provenance data."""
        analysis = {
            "platforms": [],
            "layers": [],
            "s3_endpoints": []
        }
        
        layers_to_check = []
        
        # Handle multi-arch manifests
        if manifest.get('mediaType') == 'application/vnd.docker.distribution.manifest.list.v2+json':
            self.log_debug("Processing multi-arch manifest list")
            
            for sub_manifest in manifest.get('manifests', []):
                if 'digest' in sub_manifest:
                    platform_info = sub_manifest.get('platform', {})
                    arch = platform_info.get('architecture', 'unknown')
                    os_name = platform_info.get('os', 'unknown')
                    variant = platform_info.get('variant', '')
                    
                    platform_key = f"{os_name}/{arch}"
                    if variant:
                        platform_key += f"/{variant}"
                    
                    platform_data = {
                        "platform": platform_key,
                        "manifest_digest": sub_manifest['digest'],
                        "size": sub_manifest.get('size', 0)
                    }
                    
                    # Fetch platform-specific manifest
                    platform_manifest, platform_digest_info = self.fetch_manifest_with_digest_validation(sub_manifest['digest'])
                    
                    if platform_manifest and platform_digest_info:
                        platform_data["digest"] = platform_digest_info["authoritative_digest"]
                        platform_layers = self._extract_blobs_from_manifest(platform_manifest)
                        platform_data["layer_count"] = len([b for b in platform_layers if b[0] == 'layer'])
                        # Add layers for this platform
                        layers_to_check.extend([(blob_type, digest, platform_key) for blob_type, digest in platform_layers if blob_type == 'layer'])
                    
                    analysis["platforms"].append(platform_data)
        else:
            # Single architecture manifest
            layers_to_check = [(blob_type, digest, "single-arch") for blob_type, digest in self._extract_blobs_from_manifest(manifest) if blob_type == 'layer']
        
        # Analyze each layer
        for i, (blob_type, digest, platform) in enumerate(layers_to_check):
            if i >= 10:  # Limit to first 10 layers to avoid excessive requests
                self.log_debug(f"Limiting layer analysis to first 10 layers (found {len(layers_to_check)} total)")
                break
                
            self.log_debug(f"Analyzing layer {i+1}/{min(len(layers_to_check), 10)}: {digest[:16]}...")
            
            layer_data = {
                "digest": digest,
                "platform": platform,
                "s3_endpoint": None
            }
            
            # Probe S3 storage for this layer
            s3_info = self._probe_blob_storage_with_validation(digest)
            
            if s3_info.get("s3_endpoint"):
                layer_data["s3_endpoint"] = s3_info["s3_endpoint"]
                analysis["s3_endpoints"].append(s3_info["s3_endpoint"])
            
            analysis["layers"].append(layer_data)
            
            # Small delay between requests
            time.sleep(0.1)
        
        # Remove duplicate S3 endpoints
        analysis["s3_endpoints"] = list(dict.fromkeys(analysis["s3_endpoints"]))
        
        return analysis

    def _validate_digest_format(self, digest):
        """Validate that a digest has the correct format."""
        return digest.startswith('sha256:') and len(digest) == 71 and all(c in '0123456789abcdef' for c in digest[7:])

    def _probe_blob_storage_with_validation(self, digest):
        """Probe blob storage with enhanced validation and provenance tracking."""
        blob_url = f"{self.base_url}/v2/{self.repo}/blobs/{digest}"
        result = {
            "s3_endpoint": None,
            "blob_url": None,
            "redirect_chain": [],
            "response_headers": {},
            "timing": {}
        }
        
        start_time = time.time()
        
        try:
            # Try HEAD request first
            response = self.session.head(blob_url, timeout=5, allow_redirects=False)
            result["timing"]["head_request"] = time.time() - start_time
            result["response_headers"]["head"] = dict(response.headers)
            
            if response.status_code in [301, 302, 307, 308]:
                redirect_url = response.headers.get('Location')
                if redirect_url:
                    result["redirect_chain"].append({
                        "method": "HEAD",
                        "status": response.status_code,
                        "location": redirect_url
                    })
                    
                    endpoint = self._extract_storage_endpoint_from_url(redirect_url)
                    if endpoint:
                        result["s3_endpoint"] = endpoint
                        result["blob_url"] = redirect_url
                        return result
            
            # If HEAD didn't redirect, try GET with range
            get_start_time = time.time()
            headers = {'Range': 'bytes=0-0'}
            response = self.session.get(blob_url, headers=headers, timeout=5, allow_redirects=False)
            result["timing"]["get_request"] = time.time() - get_start_time
            result["response_headers"]["get"] = dict(response.headers)
            
            if response.status_code in [301, 302, 307, 308]:
                redirect_url = response.headers.get('Location')
                if redirect_url:
                    result["redirect_chain"].append({
                        "method": "GET",
                        "status": response.status_code,
                        "location": redirect_url
                    })
                    
                    endpoint = self._extract_storage_endpoint_from_url(redirect_url)
                    if endpoint:
                        result["s3_endpoint"] = endpoint
                        result["blob_url"] = redirect_url
            
        except requests.exceptions.Timeout:
            result["error"] = "Request timeout"
        except requests.exceptions.RequestException as e:
            result["error"] = str(e)
        
        result["timing"]["total"] = time.time() - start_time
        return result

    def _extract_storage_endpoint_from_url(self, url):
        """Extract storage endpoint from a URL and return hostname."""
        parsed = urlparse(url)
        hostname = parsed.hostname
        
        if hostname and '.amazonaws.com' in hostname:
            self.s3_endpoints.add(hostname)
            self.blob_urls.add(url)
            return hostname
        
        return None

    def _extract_blobs_from_manifest(self, manifest):
        """Extract blob digests from a manifest."""
        blobs = []
        
        if 'config' in manifest and 'digest' in manifest['config']:
            blobs.append(('config', manifest['config']['digest']))
        
        for layer in manifest.get('layers', []):
            if 'digest' in layer:
                blobs.append(('layer', layer['digest']))
                
        return blobs

    def _get_available_tags(self):
        """Get list of available tags for terraform-enterprise."""
        try:
            url = f"{self.base_url}/v2/{self.repo}/tags/list"
            response = self.session.get(url, timeout=15)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    tags = data.get('tags', [])
                    return self._sort_tags_by_recency(tags)
                except json.JSONDecodeError:
                    pass
                
        except requests.exceptions.RequestException:
            pass
        
        return ['latest', 'stable']

    def _sort_tags_by_recency(self, tags):
        """Sort tags by apparent recency, with latest-style tags first."""
        if not tags:
            return []
        
        latest_tags = []
        version_tags = []
        date_tags = []
        other_tags = []
        
        for tag in tags:
            tag_lower = tag.lower()
            if tag_lower in ['latest', 'stable', 'current']:
                latest_tags.append(tag)
            elif re.match(r'^v?\d{6}(-\d+)?$', tag):
                date_tags.append(tag)
            elif re.match(r'^v?\d+\.\d+(\.\d+)?.*$', tag):
                version_tags.append(tag)
            else:
                other_tags.append(tag)
        
        def extract_date_sort_key(tag):
            match = re.search(r'(\d{4})(\d{2})(?:-(\d+))?', tag)
            if match:
                year, month, suffix = match.groups()
                return (int(year), int(month), int(suffix or 0))
            return (0, 0, 0)
        
        def extract_version_sort_key(tag):
            match = re.search(r'v?(\d+)\.(\d+)(?:\.(\d+))?', tag)
            if match:
                major, minor, patch = match.groups()
                return (int(major), int(minor), int(patch or 0))
            return (0, 0, 0)
        
        date_tags.sort(key=extract_date_sort_key, reverse=True)
        version_tags.sort(key=extract_version_sort_key, reverse=True)
        
        return latest_tags + date_tags + version_tags + other_tags

    def _generate_trust_summary(self, results):
        """Generate a summary of chain of trust validation."""
        summary = {
            "overall_trust_level": "unknown",
            "issues_found": [],
            "validation_stats": {
                "total_manifests": len(results["tags"]),
                "manifests_verified": 0,
                "total_blobs": results["summary"]["total_blobs_checked"],
                "blobs_verified": results["summary"]["digest_validation_passed"],
                "s3_redirects_working": 0,
                "s3_endpoints_discovered": len(results["s3_endpoints"])
            }
        }
        
        # Calculate trust metrics
        for tag_data in results["tags"].values():
            if tag_data.get("manifest_info", {}).get("found"):
                chain_integrity = tag_data.get("chain_integrity", {})
                
                if chain_integrity.get("manifest_digest_verified"):
                    summary["validation_stats"]["manifests_verified"] += 1
                
                summary["validation_stats"]["s3_redirects_working"] += chain_integrity.get("s3_redirects_working", 0)
        
        # Determine overall trust level
        manifest_trust = summary["validation_stats"]["manifests_verified"] / max(summary["validation_stats"]["total_manifests"], 1)
        blob_trust = summary["validation_stats"]["blobs_verified"] / max(summary["validation_stats"]["total_blobs"], 1) if summary["validation_stats"]["total_blobs"] > 0 else 1
        
        if manifest_trust >= 0.9 and blob_trust >= 0.8:
            summary["overall_trust_level"] = "high"
        elif manifest_trust >= 0.7 and blob_trust >= 0.6:
            summary["overall_trust_level"] = "medium"
        else:
            summary["overall_trust_level"] = "low"
            
        # Identify issues
        if manifest_trust < 1.0:
            summary["issues_found"].append(f"Manifest digest validation failed for {(1-manifest_trust)*100:.1f}% of manifests")
        
        if blob_trust < 0.9:
            summary["issues_found"].append(f"Blob digest validation failed for {(1-blob_trust)*100:.1f}% of blobs")
        
        if summary["validation_stats"]["s3_endpoints_discovered"] == 0:
            summary["issues_found"].append("No S3 storage endpoints discovered")
        
        return summary

    def run_discovery(self, username=None, password=None, token=None, num_tags=5, output_format="json"):
        """
        Execute the complete provenance discovery process.
        
        Args:
            username (str, optional): Registry username. If not provided, attempts to use Docker config.
            password (str, optional): Registry password. If not provided, attempts to use Docker config.
            token (str, optional): Bearer token for authentication. Takes precedence over username/password.
            num_tags (int): Number of recent tags to analyze. Default is 5.
            output_format (str): Output format - 'json', 'summary', or 'detailed'. Default is 'json'.
            
        Returns:
            dict: Discovery results containing repository info, tag analysis, and S3 endpoint mapping.
                 Structure includes:
                 - repository: Repository name analyzed
                 - registry: Registry URL
                 - discovery_timestamp: When analysis was performed
                 - tags: Per-tag analysis including manifests, platforms, and layers
                 - summary: Aggregated S3 endpoint discovery results
                 
        Raises:
            Exception: If authentication fails or discovery encounters errors.
        """
        
        if not self.setup_authentication(username, password, token):
            error_result = {"error": "Authentication required"}
            if output_format == "json":
                print(json.dumps(error_result, indent=2))
            else:
                print("Error: Authentication required")
            return error_result
        
        try:
            results = self.discover_comprehensive_provenance(num_tags)
            
            if output_format == "json":
                print(json.dumps(results, indent=2))
            elif output_format == "summary":
                self._print_summary(results)
            else:
                self._print_detailed_report(results)
                
            return results
        except Exception as e:
            error_result = {"error": f"Discovery failed: {str(e)}"}
            if output_format == "json":
                print(json.dumps(error_result, indent=2))
            else:
                print(f"Error: Discovery failed: {str(e)}")
            return error_result

    def _print_summary(self, results):
        """Print a concise summary of the provenance analysis."""
        print(f"=== HashiCorp Registry Provenance Analysis ===")
        print(f"Repository: {results['repository']}")
        print(f"Registry: {results['registry']}")
        print(f"Analysis Time: {results['discovery_timestamp']}")
        print()
        
        summary = results.get("summary", {})
        print(f"Tags Analyzed: {len(results['tags'])}")
        print(f"S3 Endpoints Discovered: {summary.get('s3_endpoint_count', 0)}")
        
        total_layers = sum(len(tag_data.get('layers', [])) for tag_data in results['tags'].values())
        print(f"Total Layers Analyzed: {total_layers}")
        print()
        
        print("S3 Endpoints:")
        for endpoint in summary.get("s3_endpoints", []):
            print(f"  • {endpoint}")

    def _print_detailed_report(self, results):
        """Print a detailed report of the provenance analysis."""
        self._print_summary(results)
        print("\n" + "="*60)
        print("DETAILED PROVENANCE ANALYSIS")
        print("="*60)
        
        for tag, tag_data in results["tags"].items():
            print(f"\nTag: {tag}")
            print("-" * 40)
            
            manifest_info = tag_data.get("manifest_info", {})
            if manifest_info.get("found"):
                print(f"Manifest Type: {manifest_info['type']}")
                print(f"Manifest Digest: {manifest_info.get('digest', 'N/A')[:16]}...")
                print(f"Manifest Size: {manifest_info.get('size', 0)} bytes")
            else:
                print("Manifest not found")
                continue
            
            platforms = tag_data.get("platforms", [])
            if platforms:
                print(f"Platforms ({len(platforms)}):")
                for platform in platforms:
                    print(f"  • {platform['platform']}: {platform.get('layer_count', 0)} layers")
            
            layers = tag_data.get("layers", [])
            if layers:
                print(f"Layers ({len(layers)} analyzed):")
                for layer in layers[:3]:  # Show first 3
                    s3_status = "→ " + layer.get('s3_endpoint', 'No S3 endpoint') if layer.get('s3_endpoint') else "No S3 redirect"
                    print(f"  • {layer['digest'][:16]}... {s3_status}")
                if len(layers) > 3:
                    print(f"  ... and {len(layers) - 3} more layers")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Analyze HashiCorp container registry provenance and S3 backend infrastructure',
        epilog='''
Examples:
  # Basic analysis with JSON output
  python3 provenance_discovery.py --output json

  # Analyze more tags with authentication  
  python3 provenance_discovery.py --username myuser --password mypass --num-tags 10

  # Quick summary of infrastructure
  python3 provenance_discovery.py --output summary

  # Detailed human-readable report
  python3 provenance_discovery.py --output detailed --debug

  # Analyze different repository
  python3 provenance_discovery.py --repo hashicorp/consul --output summary

The tool maps container images from registry manifests through to S3 storage,
providing factual data for supply chain analysis without security judgments.
        ''',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('--username', 
                       help='Registry username (or use Docker config)')
    parser.add_argument('--password', 
                       help='Registry password (or use Docker config)') 
    parser.add_argument('--token', 
                       help='Bearer token for registry authentication')
    parser.add_argument('--num-tags', type=int, default=5, 
                       help='Number of recent tags to analyze (default: 5)')
    parser.add_argument('--output', choices=['json', 'summary', 'detailed'], default='summary', 
                       help='Output format: json=machine-readable, summary=overview, detailed=full report (default: summary)')
    parser.add_argument('--debug', action='store_true', 
                       help='Enable verbose debug output during analysis')
    parser.add_argument('--repo', default='hashicorp/terraform-enterprise', 
                       help='Repository to analyze (default: hashicorp/terraform-enterprise)')
    
    args = parser.parse_args()
    
    discovery = HashiCorpProvenanceDiscovery(debug=args.debug)
    
    # Allow custom repository
    if args.repo != 'hashicorp/terraform-enterprise':
        discovery.repo = args.repo
    
    discovery.run_discovery(
        username=args.username, 
        password=args.password, 
        token=args.token, 
        num_tags=getattr(args, 'num_tags'),
        output_format=args.output
    )

if __name__ == "__main__":
    main()