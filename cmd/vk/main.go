package main

import (
	"fmt"
	"os"

	hvault "github.com/hashicorp/vault/api"
	isatty "github.com/mattn/go-isatty"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func initConfig() {
	defer viper.ReadInConfig()

	// set config name
	viper.SetConfigName("vk")

	// allow environment configuration
	viper.SetEnvPrefix("vk")
	viper.AutomaticEnv()

	// set keys
	viper.SetDefault("address", "http://127.0.0.1:8200")
	viper.BindEnv("address", "VAULT_ADDR")
	viper.BindEnv("token", "VAULT_TOKEN")
	viper.SetDefault("approle.path", "auth/approle/login")
	viper.SetDefault("token_file", "~/.vault-token")
	viper.SetDefault("token_renewal_threshold", 0.5)

	// global search paths
	viper.AddConfigPath("/etc/vk/")
	viper.AddConfigPath("/etc/")

	// local search paths
	viper.AddConfigPath("$HOME/.config/vk/")
	viper.AddConfigPath("$HOME/.config/")
}

func initLogger() zerolog.Logger {
	logger := zerolog.New(os.Stdout).With().Timestamp().Logger()
	if isatty.IsTerminal(os.Stdout.Fd()) {
		logger = logger.Output(zerolog.NewConsoleWriter())
	}
	switch viper.GetString("logLevel") {
	case "warn":
		logger = logger.Level(zerolog.WarnLevel)
	case "info":
		logger = logger.Level(zerolog.InfoLevel)
	case "debug":
		logger = logger.Level(zerolog.DebugLevel)
	case "trace":
		logger = logger.Level(zerolog.TraceLevel)
	default:
		logger = logger.Level(zerolog.InfoLevel)
	}
	return logger
}

func main() {
	// basic init
	initConfig()
	logger := initLogger()
	// create the Vault client
	vault, err := hvault.NewClient(&hvault.Config{
		Address: viper.GetString("address"),
	})
	if err != nil {
		logger.Fatal().Err(err).Msg("Unable to initialize the Vault client.")
		return
	}

	// gather prerequisites
	loginCommand := loginCommand(logger, vault)

	// root command
	mainCommand := &cobra.Command{
		Use:     "vk",
		Short:   "VaultKit is an all-in-one Hashicorp Vault scripting tool",
		Version: "pre-alpha",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// ignore unseal / login commands
			if cmd.Use == "unseal" || cmd.Use == "login" {
				return nil
			}
			// test for flags on root
			cmd = cmd.Root()
			noLogin, err := cmd.PersistentFlags().GetBool("no-auth")
			if err != nil {
				logger.Panic().Err(err).Msg("Error getting flag.")
			}
			if noLogin {
				return nil
			}
			// call login command
			return loginCommand.RunE(cmd, args)
		},
	}
	// root: flags
	mainCommand.PersistentFlags().BoolP("no-auth", "A", false, "prevents auto-login")
	// root: sub-commands
	mainCommand.AddCommand(loginCommand)

	// finally, execute
	err = mainCommand.Execute()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
