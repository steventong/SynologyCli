package main

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	"synologycli/internal/dsm"
)

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
