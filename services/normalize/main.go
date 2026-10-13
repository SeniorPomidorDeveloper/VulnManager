package main

import (
	"log/slog"
	"os"

	"vulnmanager/services/normalize/internal/app"
)

var version = "dev"

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("service", "normalize", "version", version)
	if err := app.Run(log); err != nil {
		log.Error("normalize stopped", "error", err)
		os.Exit(1)
	}
}
