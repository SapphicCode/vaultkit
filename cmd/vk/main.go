package main

import (
	"context"
	"os"
	"path"

	hvault "github.com/hashicorp/vault/api"
	isatty "github.com/mattn/go-isatty"
	"github.com/rs/zerolog"
	"github.com/spf13/viper"
	"gitlab.com/SapphicCode/vk"
)

func initConfig() {
	defer viper.ReadInConfig()

	// set config name
	viper.SetConfigName("vk")

	// allow environment configuration
	viper.SetEnvPrefix("vk")
	viper.AutomaticEnv()

	// set keys
	viper.SetDefault("address", "https://127.0.0.1:8200")
	viper.BindEnv("address", "VAULT_ADDR")
	// check for Vault token from the official Vault CLI or vk
	if homedir, err := os.UserHomeDir(); err == nil {
		vaultTokenFile := path.Join(homedir, ".vault-token")
		if stat, err := os.Stat(vaultTokenFile); err == nil && !stat.IsDir() {
			if data, err := os.ReadFile(vaultTokenFile); err == nil {
				viper.SetDefault("token", string(data))
			}
		}
	}
	viper.BindEnv("token", "VAULT_TOKEN")
	viper.SetDefault("approle.path", "auth/approle/login")

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

func login(logger zerolog.Logger, vault *hvault.Client) *hvault.Secret {
	// try token login
	token := viper.GetString("token")
	vault.SetToken(token)
	secret, err := vault.Auth().Token().LookupSelf()
	if err != nil {
		logger.Debug().Err(err).Msg("Error looking up own token.")
	} else if secret.Auth != nil {
		logger.Info().Msg("Authenticated with token.")
		// TODO: token renew logic?
		return secret
	}

	// try AppRole login
	approle := vk.AppRole{}
	viper.UnmarshalKey("approle", &approle)
	if approle.Validate() {
		logger.Info().Msg("Attempting AppRole authentication...")
		secret, err := approle.Login(context.Background(), vault)
		if err != nil {
			logger.Debug().Err(err).Msg("Error signing in with AppRole.")
		} else if secret.Auth != nil {
			logger.Info().Msg("Authenticated with AppRole.")
			return secret
		}
	}

	// try userpass login
	userpass := vk.Userpass{}
	viper.UnmarshalKey("userpass", &userpass)
	if userpass.Validate() {
		logger.Info().Msg("Attempting userpass authentication...")
		secret, err := userpass.Login(context.Background(), vault)
		if err != nil {
			logger.Debug().Err(err).Msg("Error signing in with userpass.")
		} else if secret.Auth != nil {
			logger.Info().Msg("Authenticated with userpass.")
			return secret
		}
	}

	// failure
	logger.Fatal().Msg("Unable to authenticate with Vault, exhausted all methods.")
	return nil
}

func main() {
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

	// log in
	login(logger, vault)
	// TODO: cache token to ~/.vault-token?

}
