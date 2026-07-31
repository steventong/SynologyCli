package main

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"

	"synologycli/internal/dsm"
)

func TestResolvePasswordPromptsWhenEnvironmentIsMissing(t *testing.T) {
	promptCalls := 0
	password, err := resolvePassword(
		false,
		"",
		strings.NewReader(""),
		func(string) string { return "" },
		func() (string, error) {
			promptCalls++
			return "interactive-password", nil
		},
	)
	if err != nil {
		t.Fatalf("resolvePassword() error = %v", err)
	}
	if password != "interactive-password" {
		t.Errorf("password = %q, want interactive-password", password)
	}
	if promptCalls != 1 {
		t.Errorf("prompt calls = %d, want 1", promptCalls)
	}
}

func TestResolvePasswordUsesEnvironmentForAutomation(t *testing.T) {
	promptCalls := 0
	password, err := resolvePassword(
		false,
		"CUSTOM_PASSWORD",
		strings.NewReader(""),
		func(name string) string {
			if name != "CUSTOM_PASSWORD" {
				t.Errorf("environment name = %q, want CUSTOM_PASSWORD", name)
			}
			return "environment-password"
		},
		func() (string, error) {
			promptCalls++
			return "", errors.New("unexpected prompt")
		},
	)
	if err != nil {
		t.Fatalf("resolvePassword() error = %v", err)
	}
	if password != "environment-password" {
		t.Errorf("password = %q, want environment-password", password)
	}
	if promptCalls != 0 {
		t.Errorf("prompt calls = %d, want 0", promptCalls)
	}
}

func TestResolvePasswordUsesStandardInputWhenRequested(t *testing.T) {
	password, err := resolvePassword(
		true,
		defaultPasswordEnvironment,
		strings.NewReader("stdin-password\n"),
		func(string) string { return "environment-password" },
		func() (string, error) { return "", errors.New("unexpected prompt") },
	)
	if err != nil {
		t.Fatalf("resolvePassword() error = %v", err)
	}
	if password != "stdin-password" {
		t.Errorf("password = %q, want stdin-password", password)
	}
}

func TestLoginWithOTPChallengeRetriesAfterRequired(t *testing.T) {
	var receivedOTPs []string
	login := func(otp string) (dsm.LoginResult, error) {
		receivedOTPs = append(receivedOTPs, otp)
		if otp == "" {
			return dsm.LoginResult{}, dsm.ErrOTPRequired
		}
		return dsm.LoginResult{SID: "session-id"}, nil
	}

	promptCalls := 0
	readOTP := func() (string, error) {
		promptCalls++
		return "123456", nil
	}

	result, err := loginWithOTPChallenge(login, "", readOTP, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("loginWithOTPChallenge() error = %v", err)
	}
	if result.SID != "session-id" {
		t.Errorf("result.SID = %q, want session-id", result.SID)
	}
	if promptCalls != 1 {
		t.Errorf("prompt calls = %d, want 1", promptCalls)
	}
	if want := []string{"", "123456"}; !reflect.DeepEqual(receivedOTPs, want) {
		t.Errorf("received OTPs = %v, want %v", receivedOTPs, want)
	}
}

func TestLoginWithOTPChallengeRetriesInvalidOTP(t *testing.T) {
	var receivedOTPs []string
	login := func(otp string) (dsm.LoginResult, error) {
		receivedOTPs = append(receivedOTPs, otp)
		switch len(receivedOTPs) {
		case 1:
			return dsm.LoginResult{}, dsm.ErrOTPRequired
		case 2:
			return dsm.LoginResult{}, dsm.ErrOTPInvalid
		default:
			return dsm.LoginResult{SID: "session-id"}, nil
		}
	}

	otps := []string{"111111", "222222"}
	readOTP := func() (string, error) {
		otp := otps[0]
		otps = otps[1:]
		return otp, nil
	}

	var output bytes.Buffer
	_, err := loginWithOTPChallenge(login, "", readOTP, &output)
	if err != nil {
		t.Fatalf("loginWithOTPChallenge() error = %v", err)
	}
	if want := []string{"", "111111", "222222"}; !reflect.DeepEqual(receivedOTPs, want) {
		t.Errorf("received OTPs = %v, want %v", receivedOTPs, want)
	}
	if !bytes.Contains(output.Bytes(), []byte("验证码无效或已过期")) {
		t.Errorf("output = %q, want invalid OTP message", output.String())
	}
}

func TestLoginWithOTPChallengeStopsAfterMaximumAttempts(t *testing.T) {
	loginCalls := 0
	login := func(string) (dsm.LoginResult, error) {
		loginCalls++
		return dsm.LoginResult{}, dsm.ErrOTPInvalid
	}
	readOTP := func() (string, error) {
		return "000000", nil
	}

	_, err := loginWithOTPChallenge(login, "expired", readOTP, &bytes.Buffer{})
	if !errors.Is(err, dsm.ErrOTPInvalid) {
		t.Fatalf("loginWithOTPChallenge() error = %v, want ErrOTPInvalid", err)
	}
	if loginCalls != maxOTPPromptAttempts+1 {
		t.Errorf("login calls = %d, want %d", loginCalls, maxOTPPromptAttempts+1)
	}
}
