package config

import (
	"log"
	//"strings"

	"github.com/spf13/viper"
)

type Config struct {
	Server struct {
		Port string `yaml:"port"`
	} `yaml:"server"`
	Vault struct {
		Host           string `yaml:"host"`
		Port           string `yaml:"port"`
		Scheme         string `yaml:"scheme"`
		Authentication string `yaml:"authentication"`
		Mount          string `yaml:"mount"`
		Role           string `yaml:"role"`
		Credential     struct {
			RoleID         string `mapstructure:"role-id"`
			SecretID       string `mapstructure:"secret-id"`
			Token          string `yaml:"token"`
			ServiceAccount string `yaml:"serviceaccount"`
		} `yaml:"credential"`
	} `yaml:"vault"`
}

func (c *Config) Read(path string) {
	viper.SetConfigName("config/config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.SetDefault("Server.Port", "8080")
	//Vault Defaults
	viper.SetDefault("Vault.Host", "127.0.0.1")
	viper.SetDefault("Vault.Port", "8200")
	viper.SetDefault("Vault.Scheme", "http")
	viper.SetDefault("Vault.Authentication", "token")
	//Read it
	if err := viper.ReadInConfig(); err != nil {
		log.Fatalf("Error reading config file, %s", err)
	}
	err := viper.Unmarshal(&c)
	if err != nil {
		log.Fatalf("unable to decode into struct, %v", err)
	}
}
