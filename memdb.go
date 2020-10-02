package spake2plus

import (
	"sync"
)

var mu sync.RWMutex

type UserInfo struct {
	Verifier *Verifier
}

type Lookup interface {
	Fetch(username []byte) (*UserInfo, bool)
}

// in-memory DB user Lookup implementation to be used by the Server.
// This is the place where a valid user registration is stored (identity-verifier)
// User's info should be fetched from a non-volatile DB.
// This is here primarily for tests. Don't use
type MapLookup map[string]*UserInfo

func NewMapLookup() *MapLookup {
	m := MapLookup(make(map[string]*UserInfo))
	return &m
}

// Add a user to the database with the Verifier and Group type.
func (m *MapLookup) Add(uname []byte, v *Verifier) error {
	mu.Lock()
	defer mu.Unlock()
	(*m)[string(uname)] = &UserInfo{
		Verifier: v,
	}

	return nil
}

// Context?
func (m *MapLookup) Fetch(username []byte) (*UserInfo, bool) {
	mu.RLock()
	defer mu.RUnlock()
	i, o := (*m)[string(username)]
	return i, o
}
