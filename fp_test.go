package main

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestFP(t *testing.T) {
	stmt := "select a, b, c from table1 where a = 5 and b > 6"

	fp := fingerprintSQL(stmt)
	assert.Equal(t, fp.StatementFP, "select a, b, c from table1 where a = ? and b > ?")
	assert.Equal(t, fp.SQLType, DML)
}
