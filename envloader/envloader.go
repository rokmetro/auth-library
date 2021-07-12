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

// -------------------- EnvLoader --------------------

// EnvLoader is an interface to assist with environment variable loading
type EnvLoader interface {
	// GetEnvVar returns the environment variable value with the specified key
	// 	If required and key is not found, a fatal log will be generated. Otherwise an empty string is returned
	GetEnvVar(key string, required bool) string
}

// NewEnvLoader initializes and returns the type of EnvLoader specified in the ENV_TYPE environment variable
//	The default EnvLoader is a LocalEnvLoader
func NewEnvLoader(version string, logger *loglib.StandardLogger) EnvLoader {
	env := os.Getenv("ENV_TYPE")
	switch env {
	case "aws_secrets_manager":
		secretName := os.Getenv("APP_SECRET_ARN")
		region := os.Getenv("AWS_REGION")
		return NewAwsSecretsManagerEnvLoader(secretName, region, version, logger)
	default:
		return NewLocalEnvLoader(version, logger)
	}
}

// -------------------- LocalEnvLoader --------------------

// LocalEnvLoader is an EnvLoader implementation which loads variables from the local system environment
type LocalEnvLoader struct {
	logger  *loglib.StandardLogger
	version string
}

// GetEnvVar implements EnvLoader
func (l *LocalEnvLoader) GetEnvVar(key string, required bool) string {
	value, exist := os.LookupEnv(key)
	if !exist {
		if required {
			l.logger.Fatal("No environment variable " + key)
		} else {
			l.logger.Error("No environment variable " + key)
		}
	}
	printEnvVar(key, value, l.version, l.logger)
	return value
}

// NewLocalEnvLoader instantiates a new LocalEnvLoader instance
func NewLocalEnvLoader(version string, logger *loglib.StandardLogger) *LocalEnvLoader {
	return &LocalEnvLoader{version: version, logger: logger}
}

// -------------------- AwsSecretsManagerEnvLoader --------------------

// AwsSecretsManagerEnvLoader is an EnvLoader implementation which loads variables from an AWS SecretsManager secret
type AwsSecretsManagerEnvLoader struct {
	logger  *loglib.StandardLogger
	version string

	secrets map[string]string
}

// GetEnvVar implements EnvLoader
func (a *AwsSecretsManagerEnvLoader) GetEnvVar(key string, required bool) string {
	value, exist := a.secrets[key]
	if !exist {
		if required {
			a.logger.Fatal("No environment variable " + key)
		} else {
			a.logger.Error("No environment variable " + key)
		}
	}
	printEnvVar(key, value, a.version, a.logger)
	return value
}

// NewLocalEnvLoader instantiates a new AwsSecretsManagerEnvLoader instance
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

func printEnvVar(name string, value string, version string, logger *loglib.StandardLogger) {
	if version == "dev" {
		logger.InfoWithFields("ENV_VAR", loglib.Fields{"name": name, "value": value})
	}
}
