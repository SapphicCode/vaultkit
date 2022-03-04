package main

import (
	"context"
	"errors"
	"os"

	hvault "github.com/hashicorp/vault/api"
	"github.com/mitchellh/mapstructure"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gitlab.com/SapphicCode/vk"
)

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

func login(logger zerolog.Logger, vault *hvault.Client) error {
	// try token login
	tokens := make([]string, 0, 4)
	// collect token sources
	if token := viper.GetString("token"); token != "" {
		logger.Debug().Msg("Trying config or environment as token source.")
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
				return nil
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

			return nil
		}
	}

	// try AppRole login
	approle := &vk.AppRole{}
	viper.UnmarshalKey("approle", approle)
	if approle.Validate() {
		logger.Info().Msg("Attempting AppRole authentication...")
		_, err := vault.Auth().Login(context.Background(), approle)
		if err != nil {
			logger.Debug().Err(err).Msg("Error signing in with AppRole.")
		} else {
			logger.Info().Msg("Authenticated with AppRole.")
			return nil
		}
	}

	// try userpass login
	userpass := &vk.Userpass{}
	viper.UnmarshalKey("userpass", userpass)
	if userpass.Validate() {
		logger.Info().Msg("Attempting userpass authentication...")
		_, err := vault.Auth().Login(context.Background(), userpass)
		if err != nil {
			logger.Debug().Err(err).Msg("Error signing in with userpass.")
		} else {
			logger.Info().Msg("Authenticated with userpass.")
			return nil
		}
	}

	// failure
	return errors.New("unable to authenticate with Vault, exhausted all methods")
}

func loginCommand(logger zerolog.Logger, vault *hvault.Client) *cobra.Command {
	return &cobra.Command{
		Use:   "login",
		Short: "Manually log in",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := login(logger, vault); err != nil {
				return err
			}
			saveToken(vault.Token())
			return nil
		},
	}
}
