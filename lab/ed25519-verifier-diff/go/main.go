// Lab: Go crypto/ed25519 (used by a2a-go) over the corpus. Usage: go run . CORPUS OUT
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
)

type c struct{ ID, Pk, Msg, Sig string }

func main() {
	b, _ := os.ReadFile(os.Args[1])
	var cs []c
	if err := json.Unmarshal(b, &cs); err != nil {
		panic(err)
	}
	name := "go:crypto/ed25519 [" + runtime.Version() + "]"
	res := map[string]map[string]bool{}
	for _, x := range cs {
		pk, _ := hex.DecodeString(x.Pk)
		m, _ := hex.DecodeString(x.Msg)
		s, _ := hex.DecodeString(x.Sig)
		res[x.ID] = map[string]bool{name: ed25519.Verify(ed25519.PublicKey(pk), m, s)}
	}
	o, _ := json.Marshal(res)
	os.WriteFile(os.Args[2], o, 0o644)
	fmt.Fprintln(os.Stderr, name, len(cs))
}
