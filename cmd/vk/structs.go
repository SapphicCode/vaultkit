package main

type tokenLookup struct {
	TTL         int `mapstructure:"ttl"`
	CreationTTL int `mapstructure:"creation_ttl"`
}
