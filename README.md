# WARNING - MIGRATED TO [ROKWIRE](https://github.com/rokwire/core-auth-library-go)
This library has been moved to the ROKWIRE open-source here: https://github.com/rokwire/core-auth-library-go. Please update the dependencies in all projects using this library to reflect this change. 

All future work will be done in the ROKWIRE organization, so please submit issues and pull requests on the new repository.

# auth-library
Auth library for a standard auth interface across microservices

## Installation
To install this package, use `go get`:

    go get github.com/rokmetro/auth-library

This will then make the following packages available to you:

    github.com/rokmetro/auth-library/authservice
    github.com/rokmetro/auth-library/tokenauth
    github.com/rokmetro/auth-library/sigauth

Import the `auth-library/authservice` package into your code using this template:

```go
package yours

import (
  ...

  "github.com/rokmetro/auth-library/authservice"
)

func main() {
    serviceLoader := authservice.NewRemoteServiceRegLoader("https://auth.rokmetro.com", nil)
	authService, err := authservice.NewAuthService("example", "https://sample.rokmetro.com", serviceLoader)
	if err != nil {
		log.Fatalf("Error initializing auth service: %v", err)
	}

    ...
}
```

### Staying up to date
To update auth-library to the latest version, use `go get -u github.com/rokmetro/auth-library`.
