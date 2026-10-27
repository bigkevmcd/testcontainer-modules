package dex_test

import (
	"context"
	"fmt"
	"log"

	"github.com/bigkevmcd/testcontainer-modules/dex"
	"github.com/testcontainers/testcontainers-go"
)

func ExampleRun() {
	ctx := context.Background()

	dexContainer, err := dex.Run(ctx,
		testImage,
		withDexTestConfig(),
	)
	defer func() {
		if err := testcontainers.TerminateContainer(dexContainer); err != nil {
			log.Printf("failed to terminate container: %s", err)
		}
	}()
	if err != nil {
		log.Printf("failed to start container: %s", err)
		return
	}
	// }

	state, err := dexContainer.State(ctx)
	if err != nil {
		log.Printf("failed to get container state: %s", err)
		return
	}

	fmt.Println(state.Running)

	// Output:
	// true
}
