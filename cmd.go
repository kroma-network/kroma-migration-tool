package main

import (
	"os"

	"github.com/ethereum/go-ethereum/log"
	"github.com/urfave/cli/v2"
)

func main() {
	app := cli.NewApp()
	app.Name = "Kroma MPT migration tool"
	app.Commands = cli.Commands{
		{
			Name: "migration",
			Action: func(ctx *cli.Context) error {
				StartMigration()
				return nil
			},
		},
		{
			Name: "validation",
			Action: func(ctx *cli.Context) error {
				StartValidation()
				return nil
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Crit("Application failed", "message", err)
	}
}
