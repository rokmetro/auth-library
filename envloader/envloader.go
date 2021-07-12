package envloader

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/rokmetro/logging-library/loglib"
)

type EnvLoader interface {
	GetEnvVar(key string, required bool) string
	PrintEnvVar(name string, value string)
}

func NewEnvLoader(version string, logger *loglib.StandardLogger) EnvLoader {
	env := os.Getenv("ENV_TYPE")
	switch env {
	case "aws_secrets_manager":
		secretName := os.Getenv("APP_SECRET_ARN")
		region := os.Getenv("AWS_REGION")
		return NewAwsSecretsManagerEnvLoader(secretName, region, version, logger)
	default:
		return NewLocalEnvLoader(version, *logger)
	}
}

type LocalEnvLoader struct {
	logger  *loglib.StandardLogger
	version string
}

func (l *LocalEnvLoader) GetEnvVar(key string, required bool) string {
	value, exist := os.LookupEnv(key)
	if !exist {
		if required {
			l.logger.Fatal("No environment variable " + key)
		} else {
			l.logger.Error("No environment variable " + key)
		}
	}
	l.PrintEnvVar(key, value)
	return value
}

func (l *LocalEnvLoader) PrintEnvVar(name string, value string) {
	if l.version == "dev" {
		l.logger.InfoWithFields("ENV_VAR", loglib.Fields{"name": name, "value": value})
	}
}

func NewLocalEnvLoader(version string, logger loglib.StandardLogger) *LocalEnvLoader {
	return &LocalEnvLoader{}
}

type AwsSecretsManagerEnvLoader struct {
	logger  *loglib.StandardLogger
	version string

	secrets map[string]string
}

func (a *AwsSecretsManagerEnvLoader) GetEnvVar(key string, required bool) string {
	value, exist := a.secrets[key]
	if !exist {
		if required {
			a.logger.Fatal("No environment variable " + key)
		} else {
			a.logger.Error("No environment variable " + key)
		}
	}
	a.PrintEnvVar(key, value)
	return value
}

func (a *AwsSecretsManagerEnvLoader) PrintEnvVar(name string, value string) {
	if a.version == "dev" {
		a.logger.InfoWithFields("ENV_VAR", loglib.Fields{"name": name, "value": value})
	}
}

func NewAwsSecretsManagerEnvLoader(secretName string, region string, version string, logger *loglib.StandardLogger) *AwsSecretsManagerEnvLoader {
	if secretName == "" {
		logger.Fatal("Secret name cannot be empty")
	}

	if region == "" {
		logger.Fatal("Region cannot be empty")
	}

	s, err := session.NewSession(&aws.Config{
		Region: &region,
	})
	if err != nil {
		logger.Fatalf("Error creating AWS session - Region: %s, Error: %v", secretName, region, err)
	}

	svc := secretsmanager.New(s)
	input := &secretsmanager.GetSecretValueInput{
		SecretId:     aws.String(secretName),
		VersionStage: aws.String("AWSCURRENT"),
	}

	result, err := svc.GetSecretValue(input)
	if err != nil {
		logger.Fatalf("Error loading secrets manager secret - Name: %s, Region: %s, Error: %v", secretName, region, err)
	}

	var secretConfigs map[string]string
	var secretString, decodedBinarySecret string
	if result.SecretString != nil {
		secretString = *result.SecretString
		err := json.Unmarshal([]byte(secretString), &secretConfigs)
		if err != nil {
			logger.Fatal("Failed to unmarshal secrets: " + err.Error())
		}
	} else {
		decodedBinarySecretBytes := make([]byte, base64.StdEncoding.DecodedLen(len(result.SecretBinary)))
		len, err := base64.StdEncoding.Decode(decodedBinarySecretBytes, result.SecretBinary)
		if err != nil {
			fmt.Println("Base64 Decode Error:", err)
		}
		decodedBinarySecret = string(decodedBinarySecretBytes[:len])
		err = json.Unmarshal([]byte(decodedBinarySecret), &secretConfigs)
		if err != nil {
			logger.Fatal("Failed to unmarshal secrets: " + err.Error())
		}
	}

	if secretConfigs == nil {
		logger.Fatal("Secrets are nil")
	}

	return &AwsSecretsManagerEnvLoader{secrets: secretConfigs, version: version, logger: logger}
}
