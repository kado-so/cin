package cli

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

const version = "0.0.0-dev"

func Run(args []string, stdout io.Writer, stderr io.Writer) int {
	cmd := NewRootCommand(stdout, stderr)
	cmd.SetArgs(args)

	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	return 0
}

func NewRootCommand(stdout io.Writer, stderr io.Writer) *cobra.Command {
	var showVersion bool

	root := &cobra.Command{
		Use:           "cin",
		Short:         "Encrypt app config in Git and inject it at runtime.",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if showVersion {
				fmt.Fprintln(stdout, version)
				return nil
			}

			return cmd.Help()
		},
	}

	root.SetOut(stdout)
	root.SetErr(stderr)
	root.Flags().BoolVarP(&showVersion, "version", "v", false, "show the cin version")

	root.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Show the cin version",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintln(stdout, version)
		},
	})

	return root
}
