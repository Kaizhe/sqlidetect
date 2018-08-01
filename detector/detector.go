package detector

import (
	"bufio"
	"fmt"
	"log"
	"io"
	"os/exec"
	"time"
)

const (
	Train = iota
	Detect
)

var (
	tshark = "tshark"
	cmdArgs = []string{"-i", "docker0", "-Y", "mysql.command==3", "-T", "fields", "-e", "mysql.query"}
)

type Detector struct {
	Name          string
	Model         map[SQLFP]bool
	ModelStatus   uint
	AnomalySQLMap map[AnomalySQLFP]bool
}


// NewDetector returns a new detector
func NewDetector(name string, status uint) Detector {
	return Detector{
		Name:          name,
		Model:         map[SQLFP]bool{},
		ModelStatus:   status,
		AnomalySQLMap: map[AnomalySQLFP]bool{},
	}
}

// ImportModel imports a trained to model
func (d *Detector) ImportModel(model map[SQLFP]bool) {
	d.Model = model
}

// UpdateStatus updates detector status
func (d *Detector) UpdateStatus(status uint) {
	d.ModelStatus = status
}

// ResolveAnomaly resolve anomalous SQL FP
func (d *Detector) ResolveAnomaly(fp AnomalySQLFP) {
	d.Model[fp.SqlFP] = true
	delete(d.AnomalySQLMap, fp)
}

// checkSQLFingerPrint checks SQL statement finger print
func (d *Detector) checkSQLFingerPrint(fp SQLFP) {
	if d.ModelStatus == Train {
		d.Model[fp] = true
	} else {
		if _, exists := d.Model[fp]; !exists {
			// fp never seen before
			anomalySQLFP := NewAnomalySQLFP(fp, false, time.Now().UnixNano())
			d.AnomalySQLMap[anomalySQLFP] = true
		}
	}
}

// Run detector starts to run
func (d *Detector) Run() {
	pr, pw := io.Pipe()
	defer pw.Close()

	// tell the command to write to our pipe
	cmd := exec.Command(tshark, cmdArgs...)
	cmd.Stdout = pw

	go func() {
		defer pr.Close()
		r := bufio.NewReader(pr)
		for {
			line, _, err := r.ReadLine()
			// process buf
			if err != nil && err != io.EOF {
				log.Fatal(err)
			}
			// s is the sql statement passed in from tshark
			fp := fingerprintSQL(string(line))

			d.checkSQLFingerPrint(fp)

			fmt.Println(fp.StatementFP)
		}

	}()

	// run the command, which writes all output to the PipeWriter
	// which then ends up in the PipeReader
	if err := cmd.Run(); err != nil {
		log.Fatal(err)
	}
}

