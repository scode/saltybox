package main

import (
	"context"
	"errors"
	"log"
	"os"

	"github.com/scode/saltybox/commands"
	"github.com/scode/saltybox/preader"

	"github.com/urfave/cli/v3"
)

func main() {
	var passphraseStdinArg bool
	var inputArg string
	var outputArg string
	var genOutputArg string
	var genRowsArg int
	var genSeedArg int

	getPassphraseReader := func() preader.PassphraseReader {
		if passphraseStdinArg {
			return preader.NewReader(os.Stdin)
		}
		return preader.NewTerminal()
	}

	rootCmd := &cli.Command{
		Name:        "saltybox",
		Version:     "unknown (master)",
		Usage:       "an encryption tool",
		HideVersion: true,
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:        "passphrase-stdin",
				Usage:       "Read passphrase from stdin instead of from terminal",
				Destination: &passphraseStdinArg,
			},
		},
		Commands: []*cli.Command{
			{
				Name:    "encrypt",
				Aliases: []string{"e"},
				Usage:   "Encrypt a file",
				Description: `Encrypts the contents of a file (the "input", specified with -i) and writes the encrypted output
   to another file (the "output", specified with -o).

   If the output file does not exist, it will be created. If it does exist, it will be truncated and then written to.`,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:        "input",
						Aliases:     []string{"i"},
						Usage:       "Path to the file whose contents is to be encrypted",
						Required:    true,
						Destination: &inputArg,
					},
					&cli.StringFlag{
						Name:        "output",
						Aliases:     []string{"o"},
						Usage:       "Path to the file to write the encrypted text to",
						Required:    true,
						Destination: &outputArg,
					},
				},
				Action: func(_ context.Context, _ *cli.Command) error {
					return commands.Encrypt(inputArg, outputArg, getPassphraseReader())
				},
			},
			{
				Name:    "decrypt",
				Aliases: []string{"d"},
				Usage:   "Decrypt a file",
				Description: `Decrypts the contents of a file (the "input", specified with -i) and writes the plain text output
   to another file (the "output", specified with -o).

   If the output file does not exist, it will be created. If it does exist, it will be truncated and then written to.`,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:        "input",
						Aliases:     []string{"i"},
						Usage:       "Path to the file whose contents is to be decrypted",
						Required:    true,
						Destination: &inputArg,
					},
					&cli.StringFlag{
						Name:        "output",
						Aliases:     []string{"o"},
						Usage:       "Path to the file to write the unencrypted text to",
						Required:    true,
						Destination: &outputArg,
					},
				},
				Action: func(_ context.Context, _ *cli.Command) error {
					return commands.Decrypt(inputArg, outputArg, getPassphraseReader())
				},
			},
			{
				Name:    "update",
				Aliases: []string{"u"},
				Usage:   "Update an encrypted file with new content",
				Description: `Update an existing encrypted file (the "output", specified with -o) to contain the encrypted copy
   of the input (specified with -i).

   If the output file does not already exist, or if it does not appear to be a valid saltybox file, the operation will fail.

   If the passphrase provided by the user does unlock the existing file, the operation will fail. By using the update command,
   the user thereby avoids accidentally changing the passphrase as would be possible if using the encrypt command and separately
   replacing the target file.`,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:        "input",
						Aliases:     []string{"i"},
						Usage:       "Path to the file whose contents is to be encrypted",
						Required:    true,
						Destination: &inputArg,
					},
					&cli.StringFlag{
						Name:        "output",
						Aliases:     []string{"o"},
						Usage:       "Path to the existing saltybox file to replace with encrypted text",
						Required:    true,
						Destination: &outputArg,
					},
				},
				Action: func(_ context.Context, _ *cli.Command) error {
					return commands.Update(inputArg, outputArg, getPassphraseReader())
				},
			},
			{
				Name:    "genvectors",
				Aliases: []string{"g"},
				Usage:   "Generate CSV test vectors (passphrase, plaintext, ciphertext)",
				Description: `Generates a CSV file with many test cases that exercise edge cases.

	  The CSV columns are: passphrase, plaintext, ciphertext.
	  Plaintext and ciphertext are both armored using saltybox varmor to ensure text safety.
	  The generator reuses the project's encryption and armoring primitives.`,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:        "output",
						Aliases:     []string{"o"},
						Usage:       "Path to the CSV file to write",
						Required:    true,
						Destination: &genOutputArg,
					},
					&cli.IntFlag{
						Name:        "rows",
						Aliases:     []string{"r"},
						Usage:       "Maximum number of rows to generate (default 5000)",
						Value:       5000,
						Destination: &genRowsArg,
					},
					&cli.IntFlag{
						Name:        "seed",
						Usage:       "Seed for deterministic selection of inputs (not ciphertext)",
						Value:       1,
						Destination: &genSeedArg,
					},
				},
				Action: func(_ context.Context, _ *cli.Command) error {
					return commands.GenerateVectors(genOutputArg, genRowsArg, int64(genSeedArg))
				},
			},
		},
		Action: func(_ context.Context, _ *cli.Command) error {
			return errors.New("command is required; use help to see list of commands")
		},
	}

	err := rootCmd.Run(context.Background(), os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
