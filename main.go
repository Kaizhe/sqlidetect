package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os/exec"
)

func main() {
	fmt.Println("SQLi Detector is running...")

	pr, pw := io.Pipe()
	defer pw.Close()

	// tell the command to write to our pipe
	cmd := exec.Command("tshark", "-i", "docker0", "-Y", "mysql.command==3", "-T", "fields", "-e", "mysql.query")
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
			fmt.Println(fp.StatementFP)
		}

	}()

	// run the command, which writes all output to the PipeWriter
	// which then ends up in the PipeReader
	if err := cmd.Run(); err != nil {
		log.Fatal(err)
	}
}
