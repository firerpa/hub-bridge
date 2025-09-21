# hub-bridge

The hub-bridge is a P2P Bridge, enabling firerpa devices to freely establish P2P communication with the hub. It allows devices to be connected with minimal server traffic. The hub-bridge must be deployed on a public network server and requires at least one public IPv4 address. The optimal environment is a server with both public IPv4 and IPv6 addresses. The hub-bridge features fully controllable and secure API interfaces, with granularity allowing independent IP allocation and configuration for each device.

hub-bridge 是一个网桥，让 firerpa 设备可以自由的和 hub 进行 P2P 通信，以最少的服务器流量接入您的设备，hub-bridge 需要部署于公网服务器，需要至少具备一个公网 IPV4 地址，最佳的环境是服务器同时具备公网 IPV4 + V6 地址。hub-bridge 具有完全可控且安全的 API 接口，细化到为可为每个设备分配独立 IP 和配置。

## Build docker image

```bash
docker build -t hub-bridge .
```

## First run setup

You need to remember the output key and address from the setup script. 你需要记住设置脚本的输出秘钥和地址。

```bash
docker run -it --rm -v ~/bridge:/data hub-bridge setup.sh
```

## Run hub-bridge

```bash
docker run -itd --name hub-bridge --network host --privileged --rm -v ~/bridge:/data hub-bridge
```