package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/shopspring/decimal"
)

type Pos string

var (
	Left  Pos = "left"
	Right Pos = "right"
)

type Balance map[string]decimal.Decimal

func (b Balance) Format() string {
	v, _ := json.Marshal(b) // ASCII code asc, no indent
	return string(v)
}

func (b Balance) Add(other Balance) Balance {
	r := make(Balance)
	for k, v := range b {
		r[k] = v
	}
	for k, v := range other {
		vv, ok := r[k]
		if ok {
			r[k] = v.Add(vv)
		} else {
			r[k] = v
		}
	}
	return r
}

func (b Balance) Equal(other Balance) bool {
	if len(b) != len(other) {
		return false
	}
	for k, v := range b {
		vv, ok := other[k]
		if !ok {
			return false
		}
		if !v.Equal(vv) {
			return false
		}
	}
	return true
}

func hash(v string) string {
	h := sha256.New()
	h.Write([]byte(v))
	b := h.Sum(nil)
	return hex.EncodeToString(b)
}

type MarkelProof struct {
	Root struct {
		Balances Balance
		Hash     string
	}
	Self struct {
		Balances Balance
		Nonce    string
	}
	Path []struct {
		Balances Balance
		Hash     string
		Pos      Pos
	}
}

func (m *MarkelProof) Validate() bool {
	h := hash(m.Self.Nonce + m.Self.Balances.Format())
	b := m.Self.Balances
	for _, path := range m.Path {
		if path.Hash == "" { // no right node
			h = hash(h + h + b.Format())
		} else {
			b = b.Add(path.Balances)
			if path.Pos == Left {
				h = hash(path.Hash + h + b.Format())
			} else {
				h = hash(h + path.Hash + b.Format())
			}
		}
	}

	fmt.Printf("proofed hash: %s\n", h)
	fmt.Printf("root hash: %s\n", m.Root.Hash)
	if h != m.Root.Hash {
		return false
	}
	fmt.Printf("proofed balances: %s\n", b.Format())
	fmt.Printf("root balances: %s\n", m.Root.Balances.Format())
	if !b.Equal(m.Root.Balances) {
		return false
	}
	return true
}

func main() {
	var f string
	flag.StringVar(&f, "f", "", "merkle proof file")
	flag.Parse()
	if f == "" {
		flag.Usage()
		return
	}

	b, err := os.ReadFile(f)
	if err != nil {
		fmt.Println("invalid merkle proof file", err)
		return
	}
	var m MarkelProof
	if err := json.Unmarshal(b, &m); err != nil {
		fmt.Println("invalid merkle proof file", err)
		return
	}
	if m.Root.Hash == "" || len(m.Path) == 0 {
		fmt.Println("empty merkle proof file")
		return
	}
	if m.Validate() {
		fmt.Println("Merkle tree path validation passed")
	} else {
		fmt.Println("Merkle tree path validation failed.")
	}
}
