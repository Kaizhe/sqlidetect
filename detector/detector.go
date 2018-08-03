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

const (
	timeout = 30 * time.Second
)

var (
	tshark = "tshark"
	cmdArgs = []string{"-i", "docker0", "-Y", "mysql.command==3", "-T", "fields", "-e", "mysql.query"}
	bufSize = 4 * 4 * 1024
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

// GetStatus returns the model status
func (d *Detector) GetStatus() uint {
	return d.ModelStatus
}

// UpdateStatus updates detector status
func (d *Detector) UpdateStatus(status uint) error {
	if status != Detect && status != Train {
		return fmt.Errorf("invalid status")
	}
	d.ModelStatus = status
	return nil
}

// ResolveAnomaly resolve anomalous SQL FP
func (d *Detector) ResolveAnomaly(fp AnomalySQLFP) {
	d.Model[fp.SqlFP] = true
	delete(d.AnomalySQLMap, fp)
}

// checkSQLFingerPrint checks SQL statement finger print
func (d *Detector) checkSQLFingerPrint(fp SQLFP) {
	fmt.Printf("Model Status: %d; Model Size: %d\n", d.ModelStatus, len(d.Model))
	if d.GetStatus() == Train {
		d.Model[fp] = true
	} else {
		if _, exists := d.Model[fp]; !exists {
			// fp never seen before
			anomalySQLFP := NewAnomalySQLFP(fp, false, time.Now().UnixNano())
			d.AnomalySQLMap[anomalySQLFP] = true
			fmt.Printf("Anomaly: %s\n", anomalySQLFP.SqlFP.StatementFP)
		}
	}
}

// Run detector starts to run
func (d *Detector) Run() {
	pr, pw := io.Pipe()
	t := time.NewTicker(timeout)
	defer pw.Close()

	// update model status when there is no change to the model within 30 seconds
	go func(initSize int) {
		var size, oldSize int
		oldSize = initSize
		for {
			select {
			case <-t.C:
				size = len(d.Model)
				if d.ModelStatus != Detect && size == oldSize && size > 0 {
					d.UpdateStatus(Detect)
				}
			}
			oldSize = size
			time.Sleep(1 * time.Second)
		}
	}(0)

	// tell the command to write to our pipe
	cmd := exec.Command(tshark, cmdArgs...)
	cmd.Stdout = pw

	go func() {
		defer pr.Close()
		r := bufio.NewReaderSize(pr, bufSize)
		for {
			line, _, err := r.ReadLine()

			if err != nil && err != io.EOF {
				log.Panic(err)
			}
			// line is the sql statement passed in from tshark
			fp := fingerprintSQL(string(line))

			if !fp.IsEmpty() {
				d.checkSQLFingerPrint(fp)
			}
		}

	}()

	// run the command, which writes all output to the PipeWriter
	// which then ends up in the PipeReader
	if err := cmd.Run(); err != nil {
		log.Panic(err)
	}
}

