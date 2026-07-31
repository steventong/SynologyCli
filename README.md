# Synology CLI

用于验证和调试群晖 DSM API 的 Go 命令行工具。当前实现 DS audio 使用的
`SYNO.API.Encryption` RSA 加密登录流程，并可直接编译成独立二进制文件。

## 加密登录

直接执行登录命令，CLI 会在终端中提示输入密码，输入内容不会回显，也不会进入
shell 历史或进程参数列表：

```bash
cd SynologyCli

go run ./cmd/synologycli encrypted-login \
  --server 'https://nas.example.com:5001' \
  --username 'your-account'
```

CLI 会先显示 `DSM 密码:`。账户启用了两步验证时，首次密码认证返回 OTP 挑战后，
会继续显示 `DSM 验证码:` 并自动重试；密码和验证码都使用隐藏输入。

`--server` 会自动判断输入类型：

```bash
# 完整 URL
--server 'https://nas.example.com:5001'

# IP 或域名（自动补充 https:// 和 DSM HTTPS 默认端口 5001）
--server '192.168.1.10'
--server 'nas.example.com'

# QuickConnect ID（自动通过 QuickConnect 服务发现并选择可用连接）
--server 'your-quickconnect-id'
```

无协议地址和 QuickConnect ID 默认使用 HTTPS；明确需要 HTTP 时添加 `--http`。

用于脚本或非交互环境时，可以通过 `SYNOLOGY_PASSWORD` 和 `SYNOLOGY_OTP`
预先提供凭据：

```bash
# SYNOLOGY_PASSWORD 与 SYNOLOGY_OTP 由 CI 或 secret manager 注入
go run ./cmd/synologycli encrypted-login \
  --server 'https://nas.example.com:5001' \
  --username 'your-account' \
  --password-env SYNOLOGY_PASSWORD
```

也可以使用 `--password` 从标准输入读取密码：

```bash
read -r -s password
printf '%s' "$password" | \
go run ./cmd/synologycli encrypted-login \
  --server 'https://nas.example.com:5001' \
  --username 'your-account' \
  --password
unset password
```

默认只显示掩码后的 SID/DID。测试时确实需要完整值，可以显式传入
`--show-session`。

自签名证书环境可以临时使用 `--insecure-skip-verify`，该选项会降低连接安全性，
不应在普通使用场景开启。

虽然该协议能在 HTTP 请求中隐藏账号密码，但公钥获取请求本身仍可能被中间人篡改。
CLI 允许 HTTP 以便还原和测试原版协议，但会打印安全警告，正常使用应选择 HTTPS。

## 登录与加密流程

1. 识别 `--server` 输入；QuickConnect ID 通过 `get_server_info` 解析并探测直连地址，
   无可用直连时请求 relay tunnel。
2. 调用 `SYNO.API.Info query=all` 获取当前 DSM 的 API 路径和版本。
3. 调用 `SYNO.API.Encryption getinfo` 获取动态 `cipherkey`、`ciphertoken`、服务器时间
   和 Base64 编码的 X.509 RSA 公钥。
4. URL 编码账号密码，并构造：

   ```text
   <ciphertoken>=<服务器校准后的 Unix 秒>&account=<账号>&passwd=<密码>
   ```

5. 使用 `RSA PKCS#1 v1.5` 加密上述完整内容并进行 Base64 编码。认证请求只携带：

   ```text
   <cipherkey>=<Base64 RSA 密文>
   ```

   不发送明文 `account` 或 `passwd` 字段。
6. 调用 `SYNO.API.Auth login`。DSM 返回 403 时隐藏输入 OTP，并重新获取一次性加密参数
   后重试；404 表示 OTP 无效或过期。

任何公钥解析或加密错误都会终止登录，不会降级为明文认证。

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
- DSM 403/404 能正确识别为需要 OTP/OTP 无效；
- URL、IP/域名与 QuickConnect ID 自动识别；
- QuickConnect 直连探测与 relay tunnel 回退；
- 加密失败时不会回退到明文登录。
