---
title: Misc - 233 同学的 Docker
description: 2020 | 中国科学技术大学第七届信息安全大赛 | General
---

## 题目

233 同学在软工课上学到了 Docker 这种方便的东西，于是给自己的字符串工具项目写了一个 Dockerfile。

但是 233 同学突然发现它不小心把一个私密文件（flag.txt）打包进去了，于是写了一行命令删掉这个文件。

「既然已经删掉了，应该不会被人找出来吧？」233 想道。

Docker Hub 地址：[8b8d3c8324c7/stringtool](https://hub.docker.com/r/8b8d3c8324c7/stringtool)

## 基础知识

- Docker 镜像由一系列层组成，除最后一层，其他都是只读层，每一层代表一句 Dockerfile 指令，这些层被堆叠起来，每一层都是上一层变化的增量
- 只有`RUN`、`COPY`、`ADD`指令创建新的层，其它指令只创建临时中间镜像，不增加构建的大小
- 每个镜像层在`/var/lib/docker/<storage-driver>`下都有自己的目录，包含镜像的内容

## 解题思路

- 题目中提到`于是写了一行命令删掉这个文件`，使用的应该是形如`RUN rm flag.txt`的命令，`RUN`指令会创建新的层，而非使用临时中间镜像，那么找到这一层，就可以找到`flag.txt`
- 获取各层的目录信息，镜像层为`lowerdir`，`diff`目录下包含该层的内容
    ```bash
    $ docker inspect 8b8d3c8324c7/stringtool
    [
        {
            "Id": "sha256:be6d023618d199e0ec7448f70e5e47a00c6c2b79777ad5e2d312a6f74d6ad56b",
            "RepoTags": [
                "8b8d3c8324c7/stringtool:latest"
            ],
            "RepoDigests": [
                "8b8d3c8324c7/stringtool@sha256:aef87a00ad7a4e240e4b475ea265d3818c694034c26ec227d8d4f445f3d93152"
            ],
            "Parent": "",
            "Comment": "",
            "Created": "2020-10-16T12:51:09.221320098Z",
            "Container": "d2f452fddd5c71c8c57a29d67f29c69ffac419440d57664dad6e4ba1f0eff8a1",
            "ContainerConfig": {
                ...
            },
            "DockerVersion": "19.03.5",
            "Author": "Software_Engineering_Project",
            "Config": {
                ...
            },
            "Architecture": "amd64",
            "Os": "linux",
            "Size": 1430524643,
            "VirtualSize": 1430524643,
            "GraphDriver": {
                "Data": {
                    "LowerDir": "/var/lib/docker/overlay2/6edccc4d6d8f057b4b42b8f448b9bbbd4809be182e9fa263ac4a486a08f0bedd/diff:
                    /var/lib/docker/overlay2/72c760a6faaf0c00299a0416d4a7d7892dbbe84c0d723e3cd026cf9bc23f2225/diff:
                    /var/lib/docker/overlay2/9c29b0ec3156e99f41991b01534021a575347898c6836c8077f5516ffee138af/diff:
                    /var/lib/docker/overlay2/a8721c9f92017818f0bfb114966aa0b84b543cfbefe359cfb5fd733df7e25431/diff:
                    /var/lib/docker/overlay2/ebfbfcd1df60c25be45dd84de29f38b15f39825ce5f231492a85cd857f08af31/diff:
                    /var/lib/docker/overlay2/bf646619d7607fb28d5deec60b2e340a612add9825590f34a23e8205c5d209f6/diff:
                    /var/lib/docker/overlay2/31943f86d1bbe26181f3bef8f3ae1de40f2650458ad373a8a2a71f5234d61890/diff:
                    /var/lib/docker/overlay2/29d9434b310f8c5a17746f7c8a5d56e84c631696794e752fb2e19ab2112d1534/diff:
                    /var/lib/docker/overlay2/ea91dc145974b3159822f833367282a6cff5bc4fed614146b07e931795679298/diff:
                    /var/lib/docker/overlay2/f3eb4d3cf03440fded8f1bf09c8e797472471fcacbe25217b7ce7f9ffab3f309/diff:
                    /var/lib/docker/overlay2/d47b622e362e0bbbd442de5608ef290f62e7a828c3c49ef4897c2bd6bc53cddf/diff:
                    /var/lib/docker/overlay2/edef4c3786d7fd34d6edc434c22b8d0650f640a2c1c06a0171e424302cc4b756/diff:
                    /var/lib/docker/overlay2/a9812c2890727e60f709b917d69845dd39c8bddff28651e617b35dbba0684efe/diff:
                    /var/lib/docker/overlay2/56ae36174f5ac0f1219fb9d05125d76cc418050d191de2c11710ec4045c38717/diff:
                    /var/lib/docker/overlay2/af2fc9999b37a6e0ac6aad23e8a7d3ecda2696afa36a5cf31056e37f8e416ad4/diff:
                    /var/lib/docker/overlay2/6711b59d1f347f930e92df00f5a684eca8eedce1ced9df984ccbd2232e45bb30/diff:
                    /var/lib/docker/overlay2/24373e7f69c254b21c3b16128e6055ba09a58acb8bc08cc9273c0d745dc1cc0c/diff:
                    /var/lib/docker/overlay2/8261fbe516dac64a01f9e5d213bcd42dca12e8cfb1f95a530497511a21b328f3/diff:
                    /var/lib/docker/overlay2/ce4ad073872a2365e6f364031d121b0aa174fefa565a7c7904300f638d9cf3a9/diff:
                    /var/lib/docker/overlay2/4db84c7954a7906e803b5e2bae2d0e8c3dcb7ad39f3d27822bd6bee6d42954a1/diff:
                    /var/lib/docker/overlay2/e99c01108bb370642151fbdc8209bc70c8871604a5efd2a6b9005c29160b03fe/diff:
                    /var/lib/docker/overlay2/bbe523d8bff045d3c6db194ded9773912a2a527564724c9c27393cdb47d94754/diff",
                    "MergedDir": "/var/lib/docker/overlay2/66b4f69b33d469a3d81a2fa03e1e621b8de2b9ed4ba8a756279c2d3a0a39fa7e/merged",
                    "UpperDir": "/var/lib/docker/overlay2/66b4f69b33d469a3d81a2fa03e1e621b8de2b9ed4ba8a756279c2d3a0a39fa7e/diff",
                    "WorkDir": "/var/lib/docker/overlay2/66b4f69b33d469a3d81a2fa03e1e621b8de2b9ed4ba8a756279c2d3a0a39fa7e/work"
                },
                "Name": "overlay2"
            },
            "RootFS": {
                "Type": "layers",
                "Layers": [
                    "sha256:613be09ab3c0860a5216936f412f09927947012f86bfa89b263dfa087a725f81",
                    ...
                    "sha256:ce2f773d43eee87d53a828fbcd2daa8e6ae3f0490fbaf616a8aba752839072ff"
                ]
            },
            "Metadata": {
                "LastTagTime": "0001-01-01T00:00:00Z"
            }
        }
    ]
    ```
- 通过`history`查看各层的指令，删除`flag.txt`的操作在最后一层，是相比于倒数第二层的差异，查看倒数第一层的`diff`目录
    ```bash
    $ docker history 8b8d3c8324c7/stringtool
    IMAGE               CREATED             CREATED BY                                      SIZE                COMMENT
    be6d023618d1        3 weeks ago         /bin/sh -c #(nop)  ENTRYPOINT ["/bin/sh" "-c…   0B                  # ENTRYPOINT 不创建新层
    <missing>           3 weeks ago         /bin/sh -c rm /code/flag.txt                    0B
    <missing>           3 weeks ago         /bin/sh -c #(nop) COPY dir:c36852c2989cd5e8b…   1.19kB
    <missing>           7 weeks ago         /bin/sh -c #(nop) WORKDIR /code                 0B
    <missing>           7 weeks ago         /bin/sh -c mkdir /code                          0B
    <missing>           7 weeks ago         /bin/sh -c #(nop)  ENV PYTHONUNBUFFERED=1       0B
    <missing>           7 weeks ago         /bin/sh -c pip3 install pipenv                  37.5MB
    <missing>           7 weeks ago         /bin/sh -c pip3 install bpython                 5.08MB
    <missing>           7 weeks ago         /bin/sh -c pip3 install ipython                 23.8MB
    <missing>           7 weeks ago         /bin/sh -c yum clean all                        27.9MB
    <missing>           7 weeks ago         /bin/sh -c rm -rf /tmp/Python-3.7.3*            0B
    <missing>           7 weeks ago         /bin/sh -c sed -i 's/python/python2/' /usr/b…   802B
    <missing>           7 weeks ago         /bin/sh -c pip install --upgrade pip            9.55MB
    <missing>           7 weeks ago         /bin/sh -c ln -s /usr/local/bin/pip3 /usr/bi…   19B
    <missing>           7 weeks ago         /bin/sh -c ln -s /usr/local/bin/python3 /usr…   22B
    <missing>           7 weeks ago         /bin/sh -c rm -f /usr/bin/python                0B
    <missing>           7 weeks ago         /bin/sh -c make && make install                 300MB
    <missing>           7 weeks ago         /bin/sh -c /tmp/Python-3.7.3/configure          860kB
    <missing>           7 weeks ago         /bin/sh -c tar -zxvf /tmp/Python-3.7.3.tgz -…   79.3MB
    <missing>           7 weeks ago         /bin/sh -c wget -O /tmp/Python-3.7.3.tgz htt…   23MB
    <missing>           7 weeks ago         /bin/sh -c yum -y install mariadb-devel         103MB
    <missing>           7 weeks ago         /bin/sh -c yum -y install vim                   115MB
    <missing>           7 weeks ago         /bin/sh -c yum -y install gcc                   94.8MB
    <missing>           7 weeks ago         /bin/sh -c yum-builddep python -y               316MB
    <missing>           7 weeks ago         /bin/sh -c yum -y install wget make yum-utils   92.4MB
    <missing>           7 weeks ago         /bin/sh -c #(nop)  MAINTAINER Software_Engin…   0B
    <missing>           3 months ago        /bin/sh -c #(nop)  CMD ["/bin/bash"]            0B
    <missing>           3 months ago        /bin/sh -c #(nop)  LABEL org.label-schema.sc…   0B
    <missing>           3 months ago        /bin/sh -c #(nop) ADD file:61908381d3142ffba…   203MB
    ```
- `LowerDir`中列出的层目录顺序与`history`展示的相同，查看目录即可获得 Flag
    ```bash
    $ tree /var/lib/docker/overlay2/6edccc4d6d8f057b4b42b8f448b9bbbd4809be182e9fa263ac4a486a08f0bedd/diff
    /var/lib/docker/overlay2/6edccc4d6d8f057b4b42b8f448b9bbbd4809be182e9fa263ac4a486a08f0bedd/diff
    └── code
        ├── app.py
        ├── Dockerfile
        └── flag.txt

    1 directory, 3 files
    $ cat /var/lib/docker/overlay2/6edccc4d6d8f057b4b42b8f448b9bbbd4809be182e9fa263ac4a486a08f0bedd/diff/code/flag.txt
    flag{Docker_Layers!=PS_Layers_hhh}
    ```

## 参考资料

- [Best practices for writing Dockerfiles | Docker Documentation](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/)
- [About storage drivers | Docker Documentation](https://docs.docker.com/storage/storagedriver/)
- [Use the OverlayFS storage driver | Docker Documentation](https://docs.docker.com/storage/storagedriver/overlayfs-driver/)
- [docker save | Docker Documentation](https://docs.docker.com/engine/reference/commandline/save/)