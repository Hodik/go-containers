# Lightweight Container Runtime

This project is a lightweight alternative to Docker, designed for learning purposes and experimentation. It allows you to run containers with basic isolation features, including namespaces, chroot, and networking. It also supports pulling and running Docker images from Docker Hub.

**Disclaimer**: This project is experimental and should only be run in a virtual machine (VM). It modifies networking and system configurations, which can potentially mess up your host machine's networking.

---

## Features

- **Container Isolation**: Uses Linux namespaces (`CLONE_NEWUTS`, `CLONE_NEWPID`, `CLONE_NEWNS`) for process, mount, and hostname isolation.
- **Chroot Filesystem**: Provides filesystem isolation using `chroot`.
- **Networking**: Sets up a bridge (`bridge0`) and virtual Ethernet pairs (`veth`) for container networking, with NAT for internet access.
- **Image Pulling**: Pulls Docker images from Docker Hub and extracts them into a filesystem for container execution.
- **Lightweight**: Minimalistic implementation focused on learning and experimentation.

---

## Components

1. **Main Program (`main.go`)**:
   - Handles container lifecycle (run, child, pull).
   - Pulls Docker images and extracts them into a filesystem.
   - Sets up container environment (env vars, working directory, command).

2. **Networking (`networking.go`)**:
   - Creates a bridge (`bridge0`) and virtual Ethernet pairs (`veth`).
   - Sets up network namespaces for containers.
   - Configures IP addresses, routing, and NAT for internet access.

3. **Docker Image Pulling**:
   - Authenticates with Docker Hub.
   - Fetches image manifests and layers.
   - Extracts layers into a filesystem for container execution.

---

## Prerequisites

- Linux environment (tested on Ubuntu).
- Go installed (for building the project).
- `iptables`, `ip`, and `tar` utilities installed.
- Run in a virtual machine (VM) to avoid messing up your host machine's networking.

---

## Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd <repository-directory>

---

## Running Containers

1. ```go run . run <imagename>:<tag> <command>

for example:

```go run . run library/redis:latest /bin/sh

