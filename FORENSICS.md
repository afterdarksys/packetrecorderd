# Forensics & Threat Intelligence

PacketRecorder now includes advanced forensics capabilities with optional DarkAPI and DNSScience integrations.

## Features

### Local Detection (No API Keys Required)

#### DNS Threat Detection
- **DNS Tunneling**: Detects suspicious DNS queries with:
  - Long query names (>60 characters)
  - High entropy (random-looking subdomains)
  - Excessive subdomain depth (>5 levels)
  - Suspicious TXT/NULL record queries
  
- **DGA (Domain Generation Algorithm)**: Identifies malware-generated domains using:
  - Shannon entropy analysis
  - Vowel ratio heuristics
  - Consonant cluster detection
  - Dictionary word absence

- **Fast Flux Detection**: Tracks rapid DNS IP changes indicating botnet infrastructure
  - Monitors 3+ unique IPs within 5 minutes

- **Suspicious TLDs**: Alerts on high-risk TLDs commonly used in malware:
  - `.tk`, `.ml`, `.ga`, `.cf`, `.gq` (free TLDs)
  - `.xyz`, `.top`, `.club`, `.work`, `.date`
  - `.download`, `.loan`, `.trade`, `.cricket`

#### Bot & Scraper Detection
- **User-Agent Fingerprinting**: Identifies 40+ bot signatures:
  - HTTP clients: `python-requests`, `curl`, `wget`, `axios`
  - Scrapers: `Scrapy`, `Selenium`, `Puppeteer`
  - Search engines: `googlebot`, `bingbot`, `duckduckbot`
  - Social media: `facebookexternalhit`, `twitterbot`
  - Headless browsers: `phantomjs`, `headless chrome`

#### IP Reputation
- **Datacenter Detection**: Identifies hosting/cloud IPs:
  - AWS (3.x.x.x, 52.x.x.x, 54.x.x.x ranges)
  - Google Cloud (34.x.x.x, 35.x.x.x)
  - Azure (20.x.x.x, 40.x.x.x, 104.x.x.x)
  - DigitalOcean, Vultr, Linode ranges

- **CDN Detection**: Recognizes CDN traffic:
  - Cloudflare (104.16-25.x.x, 172.64-67.x.x)
  - Fastly (151.101.x.x, 146.75.x.x)

### Enhanced Detection (with API Keys)

#### DarkAPI Integration
When `DARKAPI_API_KEY` is configured:
- **IP Reputation Lookups**: 156K+ known malicious IPs
- **Domain Intelligence**: 892K+ malware/phishing domains
- **CVE Correlation**: 45K+ tracked vulnerabilities
- **Real-time Threat Scoring**: Severity ratings and confidence levels

#### DNSScience Integration
When `DNSSCIENCE_API_KEY` is configured:
- **ISP Classification**: Residential vs datacenter detection
- **Network Type**: Cable/fiber/satellite/mobile identification
- **ASN Intelligence**: Provider and country information
- **Advanced DGA Detection**: ML-powered domain analysis

## Configuration

### Environment Variables

Create a `.env` file or export environment variables:

```bash
# DarkAPI (Optional)
export DARKAPI_API_KEY="internal-dnsscience-unlimited"
export DARKAPI_BASE_URL="https://api.darkapi.io"

# DNSScience (Optional)
export DNSSCIENCE_API_KEY="your_key_here"
export DNSSCIENCE_URL="https://dnsscience.io"
```

Get API keys:
- DarkAPI: https://console.darkapi.io
- DNSScience: https://dnsscience.io

### Running with Forensics

```bash
# With API keys (enhanced detection)
export DARKAPI_API_KEY="your_key"
sudo ./target/release/packetrecorder capture \
  --interface en0 \
  --database captures.db \
  --pcap output.pcap

# Without API keys (local detection only)
sudo ./target/release/packetrecorder capture \
  --interface en0 \
  --database captures.db
```

## Alert Types

### Existing Alerts
- `TorDetected`: Tor traffic via JA3/SNI matching
- `ChatDetected`: Encrypted messaging apps (Signal, Telegram, WhatsApp)
- `CloudStorageDetected`: Dropbox, Google Drive, OneDrive
- `HighVolumeTransfer`: Large data transfers

### New Forensics Alerts

#### DNS Threats
```
DNS TUNNELING: 192.168.1.100 -> very-long-subdomain.example.com - Reason: Long DNS query (75B)
DGA DETECTED: 192.168.1.100 -> xqzvkpwmlrt.com - score: 5, entropy: 3.45, vowels: 0.18
FAST FLUX: malware.com - 5 unique IPs in 5 min
SUSPICIOUS TLD: 192.168.1.100 -> phishing.tk - Suspicious TLD: .tk
```

#### Bot Detection
```
BOT DETECTED: 192.168.1.50 -> 1.2.3.4 - Type: Python Requests Library - UA: "python-requests/2.28.0"
BOT DETECTED: 10.0.0.25 -> example.com - Type: Scrapy Web Scraper - UA: "Scrapy/2.5.0"
```

#### IP Reputation
```
DATACENTER IP: 3.123.45.67 - Type: Hosting - Provider: None
DATACENTER IP: 104.16.123.45 - Type: Cdn - Provider: None
```

#### Threat Intelligence (with API keys)
```
MALICIOUS IP: 1.2.3.4 - Severity: high - Categories: ["C2", "Botnet"] - Source: DarkAPI
MALICIOUS DOMAIN: evil.com - Severity: critical - Categories: ["Phishing", "Malware"] - Confidence: 95%
```

## Performance

- **Local Detection**: Zero latency, no external dependencies
- **API Lookups**: 5-second timeout, graceful fallback on failure
- **Memory**: Fast flux detector keeps last 100 resolutions per domain
- **Cleanup**: Automatic stale entry removal (1 hour TTL)

## Architecture

```
PacketRecorder
├── Local Forensics (Always Active)
│   ├── DNS Threats (tunneling, DGA, TLD)
│   ├── Bot Detection (User-Agent)
│   └── IP Classification (datacenter/CDN)
│
└── API Intelligence (Optional)
    ├── DarkAPI Client (threat feeds)
    │   ├── IP reputation
    │   ├── Domain intelligence
    │   └── URL/hash lookups
    │
    └── DNSScience Client (planned)
        ├── Traffic classification
        ├── ISP identification
        └── ML-powered DGA