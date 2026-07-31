package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"golang.org/x/term"

	"synologycli/internal/dsm"
)

const (
	defaultPasswordEnvironment = "SYNOLOGY_PASSWORD"
	defaultOTPEnvironment      = "SYNOLOGY_OTP"
	maxOTPPromptAttempts       = 3
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "错误：%v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		printRootUsage(stderr)
		return errors.New("缺少子命令")
	}

	switch args[0] {
	case "encrypted-login":
		return runEncryptedLogin(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		printRootUsage(stdout)
		return nil
	default:
		printRootUsage(stderr)
		return fmt.Errorf("未知子命令 %q", args[0])
	}
}

func runEncryptedLogin(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("encrypted-login", flag.ContinueOnError)
	flags.SetOutput(stderr)

	server := flags.String("server", "", "DSM URL、IP/域名或 QuickConnect ID")
	username := flags.String("username", "", "DSM 用户名")
	passwordEnvironment := flags.String("password-env", "", "从指定环境变量读取密码（默认交互输入）")
	passwordInput := flags.Bool("password", false, "从标准输入读取密码（默认在终端中隐藏输入）")
	otpEnvironment := flags.String("otp-env", defaultOTPEnvironment, "读取预置 OTP 的环境变量名（未提供时交互输入）")
	session := flags.String("session", "AudioStation", "DSM session 名称")
	useHTTP := flags.Bool("http", false, "对无协议地址或 QuickConnect ID 使用 HTTP（默认 HTTPS）")
	timeout := flags.Duration("timeout", 15*time.Second, "每次 DSM 登录尝试的超时时间")
	insecureSkipVerify := flags.Bool("insecure-skip-verify", false, "跳过 HTTPS 证书校验（仅用于测试）")
	showSession := flags.Bool("show-session", false, "输出完整 SID/DID（敏感信息）")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "用法：synologycli encrypted-login [选项]")
		flags.PrintDefaults()
	}

	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("不接受位置参数：%s", strings.Join(flags.Args(), " "))
	}
	if strings.TrimSpace(*server) == "" {
		return errors.New("--server 必填")
	}
	if *username == "" {
		return errors.New("--username 必填")
	}
	if *timeout <= 0 {
		return errors.New("--timeout 必须大于 0")
	}

	password, err := readPassword(*passwordInput, *passwordEnvironment, stderr)
	if err != nil {
		return err
	}
	otp := ""
	if *otpEnvironment != "" {
		otp = os.Getenv(*otpEnvironment)
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	if *insecureSkipVerify {
		fmt.Fprintln(stderr, "警告：已跳过 HTTPS 证书校验，仅应在受控测试环境使用。")
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- explicit test-only CLI flag
	}
	httpClient := &http.Client{Transport: transport}

	signalContext, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	resolveContext, cancelResolve := context.WithTimeout(signalContext, *timeout)
	resolvedServer, err := dsm.ResolveServer(resolveContext, *server, !*useHTTP, httpClient)
	cancelResolve()
	if err != nil {
		return err
	}
	if resolvedServer.QuickConnect {
		fmt.Fprintln(stderr, "QuickConnect ID 已解析到可用 DSM 地址。")
	}
	if strings.HasPrefix(strings.ToLower(resolvedServer.URL), "http://") {
		fmt.Fprintln(stderr, "警告：当前使用 HTTP。RSA 可隐藏凭据，但无法阻止中间人替换公钥；建议使用 HTTPS。")
	}

	client, err := dsm.NewClient(resolvedServer.URL, httpClient)
	if err != nil {
		return err
	}

	login := func(otpCode string) (dsm.LoginResult, error) {
		ctx, cancel := context.WithTimeout(signalContext, *timeout)
		defer cancel()
		return client.EncryptedLogin(ctx, dsm.LoginRequest{
			Username: *username,
			Password: password,
			OTPCode:  otpCode,
			Session:  *session,
		})
	}

	result, err := loginWithOTPChallenge(login, otp, func() (string, error) {
		otpCode, promptErr := readOTPFromTerminal(stderr)
		if promptErr == nil && signalContext.Err() != nil {
			return "", signalContext.Err()
		}
		return otpCode, promptErr
	}, stderr)
	if err != nil {
		return err
	}

	if *showSession {
		fmt.Fprintf(stdout, "加密登录成功\nSID: %s\n", result.SID)
		if result.DID != "" {
			fmt.Fprintf(stdout, "DID: %s\n", result.DID)
		}
		return nil
	}

	fmt.Fprintf(stdout, "加密登录成功，SID=%s", maskSecret(result.SID))
	if result.DID != "" {
		fmt.Fprintf(stdout, "，DID=%s", maskSecret(result.DID))
	}
	fmt.Fprintln(stdout)
	return nil
}

func loginWithOTPChallenge(
	login func(otpCode string) (dsm.LoginResult, error),
	initialOTP string,
	readOTP func() (string, error),
	output io.Writer,
) (dsm.LoginResult, error) {
	result, err := login(initialOTP)
	for promptAttempt := 0; isOTPChallenge(err) && promptAttempt < maxOTPPromptAttempts; promptAttempt++ {
		if errors.Is(err, dsm.ErrOTPInvalid) {
			fmt.Fprintln(output, "验证码无效或已过期，请输入新的验证码。")
		} else {
			fmt.Fprintln(output, "DSM 要求进行两步验证。")
		}

		otp, readErr := readOTP()
		if readErr != nil {
			return dsm.LoginResult{}, readErr
		}
		result, err = login(otp)
	}
	if err != nil {
		if isOTPChallenge(err) {
			return dsm.LoginResult{}, fmt.Errorf("两步验证失败，已达到最多 %d 次输入次数: %w", maxOTPPromptAttempts, err)
		}
		return dsm.LoginResult{}, err
	}
	return result, nil
}

func readPassword(fromStdin bool, environmentName string, output io.Writer) (string, error) {
	return resolvePassword(
		fromStdin,
		environmentName,
		os.Stdin,
		os.Getenv,
		func() (string, error) {
			return readSecretFromTerminal(
				output,
				"DSM 密码: ",
				"DSM 密码",
				"使用 --password-env "+defaultPasswordEnvironment+" 或 --password",
				false,
			)
		},
	)
}

func resolvePassword(
	fromStdin bool,
	environmentName string,
	input io.Reader,
	getenv func(string) string,
	prompt func() (string, error),
) (string, error) {
	if fromStdin {
		content, err := io.ReadAll(io.LimitReader(input, 64<<10))
		if err != nil {
			return "", fmt.Errorf("从标准输入读取密码：%w", err)
		}
		password := strings.TrimSuffix(strings.TrimSuffix(string(content), "\n"), "\r")
		if password == "" {
			return "", errors.New("标准输入中的密码为空")
		}
		return password, nil
	}

	if environmentName != "" {
		if password := getenv(environmentName); password != "" {
			return password, nil
		}
	}
	return prompt()
}

func readOTPFromTerminal(output io.Writer) (string, error) {
	return readSecretFromTerminal(
		output,
		"DSM 验证码: ",
		"DSM 验证码",
		"通过 "+defaultOTPEnvironment+" 环境变量提供",
		true,
	)
}

func readSecretFromTerminal(output io.Writer, prompt, secretName, noninteractiveHint string, trimSpace bool) (string, error) {
	fileDescriptor := int(os.Stdin.Fd())
	if !term.IsTerminal(fileDescriptor) {
		return "", fmt.Errorf(
			"%s未提供且当前标准输入不是交互终端；请%s",
			secretName,
			noninteractiveHint,
		)
	}

	fmt.Fprint(output, prompt)
	content, err := term.ReadPassword(fileDescriptor)
	fmt.Fprintln(output)
	if err != nil {
		return "", fmt.Errorf("读取%s: %w", secretName, err)
	}

	secret := string(content)
	if trimSpace {
		secret = strings.TrimSpace(secret)
	}
	if secret == "" {
		return "", fmt.Errorf("%s不能为空", secretName)
	}
	return secret, nil
}

func isOTPChallenge(err error) bool {
	return errors.Is(err, dsm.ErrOTPRequired) || errors.Is(err, dsm.ErrOTPInvalid)
}

func maskSecret(secret string) string {
	const visible = 4
	if len(secret) <= visible*2 {
		return strings.Repeat("•", len(secret))
	}
	return secret[:visible] + "…" + secret[len(secret)-visible:]
}

func printRootUsage(output io.Writer) {
	fmt.Fprintln(output, `Synology CLI

用法：
  synologycli encrypted-login [选项]

运行 "synologycli encrypted-login -h" 查看登录选项。`)
}
