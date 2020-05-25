package argon2id_test

import (
	"testing"

	"github.com/JordanOcokoljic/argon2id"
)

func TestNewParameters(t *testing.T) {
	params, err := argon2id.NewParameters(1, 64*1024, 1, 4)
	if err != nil {
		t.Fatalf(err.Error())
	}

	if params.Time != 1 {
		t.Errorf("time parameter was not set correctly")
	}

	if params.Memory != 64*1024 {
		t.Errorf("memory parameter was not set correctly")
	}

	if params.Threads != 1 {
		t.Errorf("threads parameter was not set correctly")
	}

	if params.Length != 4 {
		t.Errorf("length parameter was not set correctly")
	}

	nParams, err := argon2id.NewParameters(1, 64*1024, 1, 4)
	if string(params.Salt) == string(nParams.Salt) {
		t.Errorf("salts were the same across two calls")
	}
}

func TestGenerateFromPassword(t *testing.T) {
	parameters, err := argon2id.NewParameters(1, 64*1024, 1, 4)
	if err != nil {
		t.Fatalf(err.Error())
	}

	parameters.Salt = []byte("SALT")

	hash, err := argon2id.GenerateFromPassword([]byte("argon"), parameters)
	if err != nil {
		t.Fatalf(err.Error())
	}

	if string(hash) != "$argon2id$v=19$m=65536,t=1,p=1$U0FMVA$kRmKhQ" {
		t.Errorf("hash %s did not match", string(hash))
	}
}

func TestGetParametersFromHash(t *testing.T) {
	hash := "$argon2id$v=19$m=65536,t=1,p=1$U0FMVA$kRmKhQ"
	params, err := argon2id.GetParametersFromHash([]byte(hash))
	if err != nil {
		t.Fatalf(err.Error())
	}

	if params.Time != 1 {
		t.Errorf("time parameter not extracted correctly")
	}

	if params.Memory != 64*1024 {
		t.Errorf("memory parameter not extracted correctly")
	}

	if params.Threads != 1 {
		t.Errorf("threads parameter not extracted correctly")
	}

	if params.Length != 4 {
		t.Errorf("length parameter not extracted correctly")
	}

	if string(params.Salt) != "SALT" {
		t.Errorf("salt not extracted correctly")
	}
}

func TestCompareHashAndPassword(t *testing.T) {
	tests := []struct {
		name     string
		hash     string
		password string
		expected error
	}{
		{
			name:     "ValidHash",
			hash:     "$argon2id$v=19$m=65536,t=1,p=1$U0FMVA$kRmKhQ",
			password: "argon",
			expected: nil,
		},
		{
			name:     "InvalidHash",
			hash:     "somefakehash",
			password: "",
			expected: argon2id.ErrorInvalidHash,
		},
		{
			name:     "InvalidVersion",
			hash:     "$argon2i$v=19$m=65536,t=1,p=1$U0FMVA$kRmKhQ",
			password: "",
			expected: argon2id.ErrorInvalidVersion,
		},
		{
			name:     "PasswordMismatch",
			hash:     "$argon2id$v=19$m=65536,t=1,p=1$U0FMVA$kRmKhQ",
			password: "Argon",
			expected: argon2id.ErrorPasswordMismatch,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(s *testing.T) {
			result := argon2id.CompareHashAndPassword(
				[]byte(test.hash),
				[]byte(test.password))

			if test.expected != nil && test.expected != result {
				s.Errorf("expected %s but was %s",
					test.expected.Error(),
					result.Error())
			}
		})
	}
}
