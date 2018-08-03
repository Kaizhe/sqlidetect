package detector

import (
	"fmt"

	sqlParser "github.com/youtube/vitess/go/vt/sqlparser"
)

const (
	// DML is SQL DML type statement
	DML = iota
	// DDL is SQL DDL type statement
	DDL
)

// SQLFP is SQL Statement Fingerprint structure
type SQLFP struct {
	StatementFP string
	SQLType     int
}

type AnomalySQLFP struct {
	SqlFP SQLFP
	Resolved bool
	Timestamp int64
}

func (fp SQLFP) IsEmpty() bool {
	return len(fp.StatementFP) == 0
}

// NewAnomalySQLFP returns a new anomalous SQL finger print
func NewAnomalySQLFP(sqlFP SQLFP, resolved bool, time int64) AnomalySQLFP {
	return AnomalySQLFP{
		sqlFP,
		resolved,
		time,
	}
}

func fingerprintSQL(matchedSQL string) SQLFP {
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

			return SQLFP{buf.ParsedQuery().Query, sqlType}

		} else {
			fmt.Printf("unrecognized SQL: %s\n", matchedSQL)
			break
		}
	}
	return SQLFP{}
}
