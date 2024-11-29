package keycloak_test

import (
	"context"
	"fmt"
	"log"

	"github.com/bigkevmcd/testcontainer-modules/keycloak"
	"github.com/testcontainers/testcontainers-go"
)

func ExampleRun() {
	ctx := context.Background()

	keycloakContainer, err := keycloak.Run(ctx,
		"quay.io/keycloak/keycloak:26.0.6-0",
	)
	defer func() {
		if err := testcontainers.TerminateContainer(keycloakContainer); err != nil {
			log.Printf("failed to terminate container: %s", err)
		}
	}()
	if err != nil {
		log.Printf("failed to start container: %s", err)
		return
	}
	// }

	state, err := keycloakContainer.State(ctx)
	if err != nil {
		log.Printf("failed to get container state: %s", err)
		return
	}

	fmt.Println(state.Running)

	// Output:
	// true
}
