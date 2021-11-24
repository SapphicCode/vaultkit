package main

import (
	"context"
	"os"

	hvault "github.com/hashicorp/vault/api"
	isatty "github.com/mattn/go-isatty"
	"github.com/mitchellh/mapstructure"
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

func tokenFilePath() string {
	tokenFilePath := viper.GetString("token_file")
	if tokenFilePath == "" {
		return ""
	}
	if tokenFilePath[0] == '~' {
		if homedir, err := os.UserHomeDir(); err == nil {
			tokenFilePath = homedir + tokenFilePath[1:]
		}
	}
	return tokenFilePath
}

func saveToken(token string) {
	tokenFile := tokenFilePath()
	if tokenFile != "" {
		os.WriteFile(tokenFile, []byte(token), 0600)
	}
}

func login(logger zerolog.Logger, vault *hvault.Client) {
	// try token login
	tokens := make([]string, 0, 4)
	// collect token sources
	if token := viper.GetString("token"); token != "" {
		tokens = append(tokens, token)
	}
	if tokenFile := tokenFilePath(); tokenFile != "" {
		logger.Debug().Str("token_file", tokenFile).Msg("Trying token file as token source.")
		data, err := os.ReadFile(tokenFile)
		if err == nil {
			tokens = append(tokens, string(data))
		}
	}
	// try authentication
	for _, token := range tokens {
		vault.SetToken(token)
		secret, err := vault.Auth().Token().LookupSelf()
		if err != nil {
			logger.Debug().Err(err).Msg("Error looking up own token.")
		} else if secret.Data != nil {
			logger.Info().Msg("Authenticated with token.")

			// determine if we should attempt renewal
			lookup := &tokenLookup{}
			if err := mapstructure.Decode(secret.Data, lookup); err != nil {
				logger.Err(err).Msg("Unable to decode token lookup.")
				return
			}

			tokenLifespan := float32(lookup.TTL) / float32(lookup.CreationTTL)
			if tokenLifespan < float32(viper.GetFloat64("token_renewal_threshold")) {
				secret, _ := vault.Logical().Write("auth/token/renew-self", nil)
				if len(secret.Warnings) == 0 {
					logger.Debug().Msg("Renewed token.")
				} else {
					logger.Debug().Msgf("Unable to renew token.")
				}
			} else {
				logger.Debug().Float32("lifespan", tokenLifespan).Msg("Not attempting to renew token.")
			}

			return
		}
	}

	// try AppRole login
	approle := &vk.AppRole{}
	viper.UnmarshalKey("approle", approle)
	if approle.Validate() {
		logger.Info().Msg("Attempting AppRole authentication...")
		secret, err := vault.Auth().Login(context.Background(), approle)
		if err != nil {
			logger.Debug().Err(err).Msg("Error signing in with AppRole.")
		} else if secret.Auth != nil {
			logger.Info().Msg("Authenticated with AppRole.")
			return
		}
	}

	// try userpass login
	userpass := &vk.Userpass{}
	viper.UnmarshalKey("userpass", userpass)
	if userpass.Validate() {
		logger.Info().Msg("Attempting userpass authentication...")
		secret, err := vault.Auth().Login(context.Background(), userpass)
		if err != nil {
			logger.Debug().Err(err).Msg("Error signing in with userpass.")
		} else if secret.Auth != nil {
			logger.Info().Msg("Authenticated with userpass.")
			return
		}
	}

	// failure
	logger.Fatal().Msg("Unable to authenticate with Vault, exhausted all methods.")
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
	saveToken(vault.Token())
}
