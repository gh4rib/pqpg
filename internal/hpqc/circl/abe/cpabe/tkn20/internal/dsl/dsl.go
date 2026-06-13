package dsl

import "github.com/gh4rib/pqpg/internal/hpqc/circl/abe/cpabe/tkn20/internal/tkn"

var AttrHashKey = []byte("attribute value hashing")

func Run(source string) (*tkn.Policy, error) {
	l := newLexer(source)
	err := l.scanTokens()
	if err != nil {
		return nil, err
	}
	p := newParser(l.tokens)
	ast, err := p.parse()
	if err != nil {
		return nil, err
	}
	return ast.RunPasses()
}
