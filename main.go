package main

import (
	"fmt"

	"sqlidetect/detector"
)

func main() {
	fmt.Println("SQLi Detector is running...")

	detector := detector.NewDetector("My Detector", detector.Train)
	detector.Run()
}
