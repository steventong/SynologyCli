# Synology CLI

用于验证和调试群晖 DSM API 的 Go 命令行工具。当前实现 DS audio 使用的
`SYNO.API.Encryption` RSA 加密登录流程，并可直接编译成独立二进制文件。

## 加密登录

密码默认从 `SYNOLOGY_PASSWORD` 环境变量读取，不通过命令行参数传递，避免进入
进程参数列表。以下示例使用隐藏输入，也不会把密码字面量写进 shell 历史。

```bash
cd SynologyCli

read -r -s SYNOLOGY_PASSWORD
export SYNOLOGY_PASSWORD
go run ./cmd/synologycli encrypted-login \
  --server 'https://nas.example.com:5001' \
  --username 'your-account'
unset SYNOLOGY_PASSWORD
```

需要 OTP 时：

```bash
read -r -s SYNOLOGY_PASSWORD
read -r -s SYNOLOGY_OTP
export SYNOLOGY_PASSWORD SYNOLOGY_OTP
go run ./cmd/synologycli encrypted-login \
  --server 'https://nas.example.com:5001' \
  --username 'your-account'
unset SYNOLOGY_PASSWORD SYNOLOGY_OTP
```

也可以从标准输入读取密码：

```bash
read -r -s password
printf '%s' "$password" | \
go run ./cmd/synologycli encrypted-login \
  --server 'https://nas.example.com:5001' \
  --username 'your-account' \
  --password-stdin
unset password
```

默认只显示掩码后的 SID/DID。测试时确实需要完整值，可以显式传入
`--show-session`。

自签名证书环境可以临时使用 `--insecure-skip-verify`，该选项会降低连接安全性，
不应在普通使用场景开启。

虽然该协议能在 HTTP 请求中隐藏账号密码，但公钥获取请求本身仍可能被中间人篡改。
CLI 允许 HTTP 以便还原和测试原版协议，但会打印安全警告，正常使用应选择 HTTPS。

## 构建

```bash
go build -o ./bin/synologycli ./cmd/synologycli
./bin/synologycli help
```

## 测试

```bash
go test ./...
```

测试会启动本地模拟 DSM 服务，生成临时 RSA 密钥，并在服务端解密登录请求，验证：

- 登录请求不包含明文 `account` / `passwd` 字段；
- RSA 算法为 PKCS#1 v1.5；
- 动态 `cipherkey`、`ciphertoken` 和服务器校准时间正确；
- 加密失败时不会回退到明文登录。
