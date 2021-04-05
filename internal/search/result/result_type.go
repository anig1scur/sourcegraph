package result

import (
	"strings"
)

// Types represents a set of result types.
// It's a bitset corresponding to the disjunction of types it represents.
//
// For example, the set of file and repo results
// is represented as Types(TypeFile|TypeRepo)
type Types uint8

const (
	TypeEmpty Types = 0
	TypeRepo  Types = 1 << (iota - 1)
	TypeSymbol
	TypeFile
	TypePath
	TypeDiff
	TypeCommit
)

var TypeFromString = map[string]Types{
	"repo":   TypeRepo,
	"symbol": TypeSymbol,
	"file":   TypeFile,
	"path":   TypePath,
	"diff":   TypeDiff,
	"commit": TypeCommit,
}

func (r Types) Has(t Types) bool {
	return r&t != 0
}

func (r Types) With(t Types) Types {
	return r | t
}

func (r Types) Without(t Types) Types {
	return r &^ t
}

func (r Types) String() string {
	var names []string
	if r.Has(TypeFile) {
		names = append(names, "file")
	}
	if r.Has(TypePath) {
		names = append(names, "path")
	}
	if r.Has(TypeRepo) {
		names = append(names, "repo")
	}
	if r.Has(TypeSymbol) {
		names = append(names, "symbol")
	}
	if r.Has(TypeDiff) {
		names = append(names, "diff")
	}
	if r.Has(TypeCommit) {
		names = append(names, "commit")
	}
	return strings.Join(names, "|")
}
