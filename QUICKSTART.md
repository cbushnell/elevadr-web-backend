# eleVADR Quick Start Guide

Get up and running with eleVADR in minutes using Docker.

## Prerequisites

- Docker installed ([Get Docker](https://docs.docker.com/get-docker/))
- A PCAP file to analyze

## 3-Step Quick Start

### 1. Build the Container

```bash
git clone <repository-url>
cd eleVADR
docker build -t elevadr:latest .
```

Build time: ~5-10 minutes (one-time setup)

### 2. Prepare Your PCAP

```bash
# Create directories
mkdir -p pcaps reports

# Copy your PCAP file
cp /path/to/your/network-capture.pcap pcaps/capture.pcap
```

### 3. Run Analysis

```bash
docker run --rm \
  -v $(pwd)/pcaps:/input:ro \
  -v $(pwd)/reports:/output \
  elevadr:latest
```

### 4. View Results

```bash
# View the report
cat reports/report.json

# Or pretty-print with jq
cat reports/report.json | jq .
```

## What You'll Get

The JSON report includes:

- **Device Panel**: Total hosts, OT devices, cross-segment communications
- **Service Panel**: Known services, OT protocols, risky services
- **Risk Analysis**: Services categorized by security risk
- **Suspicious Activity**: Unexpected outbound connections
- **OT Insights**: Industrial protocol usage and manufacturers

## Example Output

```json
{
  "modules": {
    "device_panel": {
      "hosts": 42,
      "ot_hosts": 15,
      "ot_cross_segment": 3
    },
    "service_panel": {
      "num_known_services": 28,
      "num_ot_services": 8,
      "num_risky_services": 5,
      "num_unknown_services": 2
    }
  }
}
```

## Common Use Cases

### Analyze Multiple PCAPs

```bash
# Analyze each PCAP in a directory
for pcap in /path/to/pcaps/*.pcap; do
  filename=$(basename "$pcap" .pcap)
  docker run --rm \
    -v $(dirname "$pcap"):/input:ro \
    -v $(pwd)/reports:/output \
    -e PCAP_INPUT=/input/$(basename "$pcap") \
    -e REPORT_OUTPUT=/output/report-$filename.json \
    elevadr:latest
done
```

### Using Docker Compose

```bash
# Simpler syntax with docker-compose
cp your-capture.pcap pcaps/capture.pcap
docker-compose up elevadr

# View reports in browser
docker-compose --profile web-server up -d
open http://localhost:8080
```

### Resource-Constrained Environments

```bash
# Limit CPU and memory usage
docker run --rm \
  --cpus="1" \
  --memory="2g" \
  -v $(pwd)/pcaps:/input:ro \
  -v $(pwd)/reports:/output \
  elevadr:latest
```

## Next Steps

### Production Deployment

For production use with Kubernetes:

1. Push image to registry:
   ```bash
   docker tag elevadr:latest your-registry/elevadr:latest
   docker push your-registry/elevadr:latest
   ```

2. Deploy to Kubernetes:
   ```bash
   kubectl apply -k k8s/
   ```

See [DOCKER.md](DOCKER.md) for complete Kubernetes deployment guide.

### Customization

- **Custom reference data**: Mount your own ports.json, port_risk.json
- **Different output format**: Modify app/utils/report.py
- **Additional analysis**: Extend app/utils/analysis.py

### Troubleshooting

| Issue | Solution |
|-------|----------|
| "PCAP not found" | Ensure file is named `capture.pcap` or set `PCAP_INPUT` env var |
| Out of memory | Increase `--memory` limit or use smaller PCAP |
| Slow processing | Large PCAPs take time; monitor with `docker logs` |

## Getting Help

- Full documentation: [README.md](README.md)
- Docker & Kubernetes guide: [DOCKER.md](DOCKER.md)
- Issues: [GitHub Issues](https://github.com/your-org/eleVADR/issues)

## Makefile Commands

For convenience, use the included Makefile:

```bash
make build          # Build Docker image
make run           # Run analysis
make web-server    # Start report viewer
make clean         # Clean up
make help          # Show all commands
```

---

**That's it!** You're now analyzing OT network security with eleVADR.
