package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// bindEnv lets every flag fall back to an environment variable, so a Tekton
// Task can pass configuration either way. Flags win: an explicitly passed flag
// is never overridden by the environment.
//
// The mapping is explicit rather than derived from the flag name, because the
// env var names are an existing contract with the Tekton Tasks these tools
// replace and must not be guessed at.
func bindEnv(cmd *cobra.Command, mapping map[string]string) error {
	var err error
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		if err != nil || f.Changed {
			return
		}
		env, ok := mapping[f.Name]
		if !ok {
			return
		}
		val, ok := os.LookupEnv(env)
		if !ok || val == "" {
			return
		}
		if setErr := f.Value.Set(val); setErr != nil {
			err = fmt.Errorf("%s=%q is not valid for --%s: %w", env, val, f.Name, setErr)
		}
	})
	return err
}
