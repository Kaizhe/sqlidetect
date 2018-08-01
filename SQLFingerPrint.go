package main

import (
	"log"

	sqlParser "github.com/youtube/vitess/go/vt/sqlparser"
)

const (
	// DML is SQL DML type statement
	DML = iota
	// DDL is SQL DDL type statement
	DDL
)

// SQLStatementFP is SQL Statement Fingerprint structure
type SQLStatementFP struct {
	StatementFP string
	SQLType     int
}

func fingerprintSQL(matchedSQL string) SQLStatementFP {
	var sqlType int

	tokens := sqlParser.NewStringTokenizer(matchedSQL)
	for {
		stmt, err := sqlParser.ParseNext(tokens)
		//if err == io.EOF {
		//	break
		//}

		if err == nil {
			buf := sqlParser.NewTrackedBuffer(nil)
			buf.Myprintf("%v", stmt)

			switch stmt.(type) {
			case *sqlParser.Select:
				sqlType = DML
			case *sqlParser.Insert:
				sqlType = DML
			case *sqlParser.Update:
				sqlType = DML
			case *sqlParser.Delete:
				sqlType = DML
			default:
				sqlType = DDL // treat all non-DML sql statements as DDL for now
			}

			// walk through the parsed nodes in the SQL statement and replace the value node with ?
			_ = sqlParser.Walk(func(node sqlParser.SQLNode) (kontinue bool, err error) {
				switch node := node.(type) {
				case *sqlParser.SQLVal:
					node.Val = []byte("?")
				}

				return true, nil
			}, stmt)

			// rest buffer to empty
			buf.Reset()
			buf.Myprintf("%v", stmt)

			return SQLStatementFP{buf.ParsedQuery().Query, sqlType}

		} else {
			log.Println("something wrong here: " + matchedSQL)
			break
		}
	}
	return SQLStatementFP{}
}
