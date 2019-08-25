package main

import (
	"errors"
	"github.com/scode/saltybox/commands"
	"github.com/scode/saltybox/preader"
	"log"
	"os"

	"github.com/urfave/cli"
)

func main() {
	app := cli.NewApp()
	app.Name = "saltybox"
	app.Version = "unknown (master)"
	app.Usage = "an encryption tool"
	app.HideVersion = true

	var passphraseStdinArg bool
	getPassphraseReader := func() preader.PassphraseReader {
		if passphraseStdinArg {
			return preader.NewReader(os.Stdin)
		}

		return preader.NewTerminal()
	}

	var inputArg string
	var outputArg string

	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:        "passphrase-stdin",
			Usage:       "Read passphrase from stdin instead of from terminal",
			Destination: &passphraseStdinArg,
		},
	}

	app.Commands = []cli.Command{
		{
			Name:    "encrypt",
			Aliases: []string{"e"},
			Usage:   "Encrypt a file",
			Description: `Encrypts the contents of a file (the "input", specified with -i) and writes the encrypted output
   to another file (the "output", specified with -o).

   If the output file does not exist, it will be created. If it does exist, it will be truncated and then written to.`,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:        "input, i",
					Usage:       "Path to the file whose contents is to be encrypted",
					Required:    true,
					Destination: &inputArg,
				},
				cli.StringFlag{
					Name:        "output, o",
					Usage:       "Path to the file to write the encrypted text to",
					Required:    true,
					Destination: &outputArg,
				},
			},
			Action: func(c *cli.Context) error {
				return commands.PassphraseEncryptFile(inputArg, outputArg, getPassphraseReader())
			},
		},
		{
			Name:    "decrypt",
			Aliases: []string{"e"},
			Usage:   "Decrypt a file",
			Description: `Decrypts the contents of a file (the "input", specified with -i) and writes the plain text output
   to another file (the "output", specified with -o).

   If the output file does not exist, it will be created. If it does exist, it will be truncated and then written to.`,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:        "input, i",
					Usage:       "Path to the file whose contents is to be decrypted",
					Required:    true,
					Destination: &inputArg,
				},
				cli.StringFlag{
					Name:        "output, o",
					Usage:       "Path to the file to write the unencrypted text to",
					Required:    true,
					Destination: &outputArg,
				},
			},
			Action: func(c *cli.Context) error {
				return commands.PassphraseDecryptFile(inputArg, outputArg, getPassphraseReader())
			},
		},
		{
			Name:    "update",
			Aliases: []string{"e"},
			Usage:   "Update an encrypted file with new content",
			Description: `Update an existing encrypted file (the "output", specified with -o) to contain the encrypted copy
   of the input (specified with -i).

   If the output file does not already exist, or if it does not appear to be a valid saltybox file, the operation will fail.

   If the passphrase provided by the user does unlock the existing file, the operation will fail. By using the update command,
   the user thereby avoids accidentally changing the passphrase as would be possible if using the encrypt command and separately
   replacing the target file.`,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:        "input, i",
					Usage:       "Path to the file whose contents is to be encrypted",
					Required:    true,
					Destination: &inputArg,
				},
				cli.StringFlag{
					Name:        "output, o",
					Usage:       "Path to the existing saltybox file to replace with encrypted text",
					Required:    true,
					Destination: &outputArg,
				},
			},
			Action: func(c *cli.Context) error {
				return commands.PassphraseUpdateFile(inputArg, outputArg, getPassphraseReader())
			},
		},
	}

	app.Action = func(c *cli.Context) error {
		return errors.New("command is required; use help to see list of commands")
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
