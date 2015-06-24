# GoogleTest

Test available Google IPs.

快速准确的 Google IP 测试工具，需要 Python 3.3 以上版本。

## Google 服务器测试工具

    用法: googletest.py [-h] [-n NUM] [-w WORKERS] [-t] [-o] [file] > hosts.txt

    固定参数:
      file                  Google IP 列表文件 (可用随附的 googleip.txt)

    可选参数:
      -h, --help            显示帮助信息并退出
      -n NUM, --num NUM     测试多少 IP (默认 100000)
      -w WORKERS, --workers WORKERS
                            并发多少线程 (默认 100)
      -t, --time            输出连接时间
      -o, --hosts           输出 hosts 格式 (无通配符)

稍等片刻，于标准输出可获得带域名的 IP 列表。

## Unbound 插件

若安装有 Unbound DNS 服务器，配合 `staticdns.py` 插件可获得无缝自由连接体验。

Unbound 需带有 Python 模块支持： --with-pythonmodule

### 示例服务器

运行 `./testrun.sh`

    nslookup -port=6053 google.com 127.0.0.1

### 配置说明

#### unbound.conf

    server:
        # ...
        module-config: "validator python iterator"
        # ...

    # ...

    python:
        # Script file to load
        python-script: "/etc/unbound/staticdns.py"  # 填入该文件的真实路径

#### staticdns.py

修改文件中 HOSTS 变量为测试工具输出文件所在的路径。
