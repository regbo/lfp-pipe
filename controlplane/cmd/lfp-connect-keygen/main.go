// Command lfp-connect-keygen creates the NATS Account and XKey material used by
// the Auth Callout. It emits only public keys and keeps private seeds in files.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/nats-io/nkeys"
)

type publicKeys struct {
	Issuer string `json:"issuer"`
	XKey   string `json:"xkey"`
}

func main() {
	secretDir := flag.String("secret-dir", "", "protected directory for generated key material")
	flag.Parse()
	if *secretDir == "" {
		fatal(errors.New("--secret-dir is required"))
	}
	if err := os.MkdirAll(*secretDir, 0o700); err != nil {
		fatal(fmt.Errorf("create secret directory: %w", err))
	}

	issuer, err := ensureKey(filepath.Join(*secretDir, "nats-auth-issuer-seed"), nkeys.CreateAccount)
	if err != nil {
		fatal(err)
	}
	xkey, err := ensureKey(filepath.Join(*secretDir, "nats-auth-xkey-seed"), nkeys.CreateCurveKeys)
	if err != nil {
		fatal(err)
	}
	issuerPublic, err := issuer.PublicKey()
	if err != nil {
		fatal(fmt.Errorf("derive issuer public key: %w", err))
	}
	xkeyPublic, err := xkey.PublicKey()
	if err != nil {
		fatal(fmt.Errorf("derive xkey public key: %w", err))
	}

	keys := publicKeys{Issuer: issuerPublic, XKey: xkeyPublic}
	encoded, err := json.MarshalIndent(keys, "", "  ")
	if err != nil {
		fatal(err)
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile(filepath.Join(*secretDir, "nats-public.json"), encoded, 0o600); err != nil {
		fatal(fmt.Errorf("write public key metadata: %w", err))
	}
	if err := json.NewEncoder(os.Stdout).Encode(keys); err != nil {
		fatal(err)
	}
}

func ensureKey(path string, create func() (nkeys.KeyPair, error)) (nkeys.KeyPair, error) {
	if seed, err := os.ReadFile(path); err == nil {
		key, parseErr := nkeys.FromSeed(seed)
		if parseErr != nil {
			return nil, fmt.Errorf("parse existing seed %s: %w", path, parseErr)
		}
		return key, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read seed %s: %w", path, err)
	}

	key, err := create()
	if err != nil {
		return nil, fmt.Errorf("generate NKey: %w", err)
	}
	seed, err := key.Seed()
	if err != nil {
		return nil, fmt.Errorf("encode NKey seed: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create seed file %s: %w", path, err)
	}
	if _, err = file.Write(append(seed, '\n')); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("write seed file %s: %w", path, err)
	}
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("close seed file %s: %w", path, err)
	}
	return key, nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
