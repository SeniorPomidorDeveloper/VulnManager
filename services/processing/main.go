package main

import (
	"log/slog"
	"os"

	"vulnmanager/services/processing/internal/app"
)

var version = "dev"

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("service", "processing", "version", version)
	if err := app.Run(log); err != nil {
		log.Error("processing stopped", "error", err)
		os.Exit(1)
	}
}
