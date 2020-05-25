package argon2id

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

var (
	// ErrorInvalidHash indicates that the provided hash does not conform to
	// any argon2 standard.
	ErrorInvalidHash = fmt.Errorf("argon2id: invalid hash provided")

	// ErrorInvalidVersion indicates that the provided has may be an argon hash
	// but is not an argon2id hash.
	ErrorInvalidVersion = fmt.Errorf("argon2id: non argon2id hash provided")

	// ErrorPasswordMismatch indicates that the provided hash and password do
	// not match.
	ErrorPasswordMismatch = fmt.Errorf("argon2id: password did not match")
)

// Parameters is a collection of parameters that control the output of the
// hash.
type Parameters struct {
	Time    uint32
	Memory  uint32
	Threads uint8
	Length  uint32
	Salt    []byte
}

// NewParameters genreates a new Parameters struct and initializes it with
// the provided values and a randomly generated salt.
func NewParameters(
	time uint32,
	memory uint32,
	threads uint8,
	length uint32,
) (Parameters, error) {

	p := Parameters{}
	p.Salt = make([]byte, length)
	if _, err := rand.Read(p.Salt); err != nil {
		return p, err
	}

	p.Time = time
	p.Memory = memory
	p.Threads = threads
	p.Length = length

	return p, nil
}

// GenerateFromPassword takes a password and parameter struct and encodes the
// password with Argon2id, based on the parameters set in the struct.
func GenerateFromPassword(password []byte, p Parameters) ([]byte, error) {
	hash := argon2.IDKey(
		password,
		p.Salt, p.Time, p.Memory, p.Threads, p.Length)

	eSalt := base64.RawStdEncoding.EncodeToString(p.Salt)
	eHash := base64.RawStdEncoding.EncodeToString(hash)

	out := fmt.Sprintf(
		"$argon2id$v=%d$m%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		p.Memory, p.Time, p.Threads,
		eSalt, eHash)

	return []byte(out), nil
}

// GetParametersFromHash will read an Argon2id hash and return a parameters
// object with the parameters that were used to generate the hash.
func GetParametersFromHash(hash []byte) (Parameters, error) {
	sections := strings.Split(string(hash), "$")
	p := Parameters{}
	_, err := fmt.Sscanf(
		sections[3],
		"m%d,t=%d,p=%d",
		&p.Memory, &p.Time, &p.Threads)

	if err != nil {
		return p, err
	}

	salt, err := base64.RawStdEncoding.DecodeString(sections[4])
	if err != nil {
		return p, err
	}

	p.Length = uint32(len(salt))
	p.Salt = salt
	return p, nil
}

// CompareHashAndPassword compares a hashed Argon2id password with a possible
// plaintext equivalent. Returns nil on success, or an error on failure.
func CompareHashAndPassword(hash, password []byte) error {
	sections := strings.Split(string(hash), "$")
	if len(sections) != 6 {
		return ErrorInvalidHash
	}

	if sections[1] != "argon2id" {
		return ErrorInvalidVersion
	}

	dHash, err := base64.RawStdEncoding.DecodeString(sections[5])
	if err != nil {
		return err
	}

	p, err := GetParametersFromHash(hash)
	if err != nil {
		return err
	}

	cHash := argon2.IDKey(
		password, p.Salt,
		p.Time, p.Memory, p.Threads, p.Length)

	if subtle.ConstantTimeCompare(dHash, cHash) != 1 {
		return ErrorPasswordMismatch
	}

	return nil
}
