# **hub-bridge** ｜ P2P Bridge for FIREPRA

<img src="logo.svg" alt="FIRERPA" width="200" align="right" />

The hub-bridge is a P2P Bridge, enabling firerpa devices to freely establish P2P communication with the hub or other devices. It allows devices to be connected with minimal server traffic. The hub-bridge must be deployed on a public network server and requires at least one public IPv4 address. The optimal environment is a server with both public IPv4 and IPv6 addresses. The hub-bridge features fully controllable and secure API interfaces, with granularity allowing independent IP allocation and configuration for each device.

## Build docker image

```bash
docker build -t hub-bridge .
```

## First run setup

You need to remember (save) the key and address output by the setup script, and make sure to properly open the required ports and protocols according to the firewall rules shown in the output.

```bash
docker run -it --rm -v ~/bridge:/data hub-bridge setup.sh
```

## Run hub-bridge

```bash
docker run -itd --name hub-bridge --network host --privileged --rm -v ~/bridge:/data hub-bridge
```