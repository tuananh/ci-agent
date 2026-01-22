# CI Agent

eBPF-based egress audit tool for CI environments. Captures outbound network connections with executable paths and DNS hostnames.

## Usage

```bash
make                                    # Build
sudo ./ci-agentd                        # Run daemon
nc -U /run/ci-agent.sock                # View logs (in another terminal)
dig google.com                          # Test DNS capture
curl https://www.github.com             # Generate traffic
```
