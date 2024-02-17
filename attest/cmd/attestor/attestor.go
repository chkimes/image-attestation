package cmd

import (
	"fmt"
	"os"

	"github.com/chkimes/image-attestation/internal"
	"github.com/in-toto/scai-demos/scai-gen/pkg/fileio"

	//slsa "github.com/in-toto/attestation/go/predicates/provenance/v1"
	ita "github.com/in-toto/attestation/go/v1"
	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "image-attestor",
	Args:  cobra.ExactArgs(1),
	Short: "Generates a JSON-encoded image attestation (in-toto format)",
	RunE:  genAttestation,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

var (
	outFile      string
	prettyPrint  bool
	evidenceFile string
)

func init() {
	rootCmd.Flags().StringVarP(
		&outFile,
		"out-file",
		"o",
		"",
		"Filename to write out the JSON-encoded object",
	)
	rootCmd.MarkFlagRequired("out-file") //nolint:errcheck

	rootCmd.Flags().StringVarP(
		&evidenceFile,
		"evidence",
		"e",
		"",
		"The filename of the JSON-encoded evidence resource descriptor",
	)

	rootCmd.Flags().BoolVar(
		&prettyPrint,
		"pretty-print",
		false,
		"Flag to JSON pretty-print the generated Report",
	)
}

func genAttestation(_ *cobra.Command, args []string) error {
	// want to make sure the AttributeAssertion is a JSON file
	if !fileio.HasJSONExt(outFile) {
		return fmt.Errorf("expected a .json extension for the generated SCAI AttributeAssertion file %s", outFile)
	}

	// read in the subject file
	//subjectFile := args[0]
	//subject, err := generators.NewRdForFile(subjectFile, "", "", "sha256", false, "", "", nil)
	//if err != nil {
	//	return fmt.Errorf("error generating RD for subject %s: %w", subjectFile, err)
	//}

	// generate dummy VM instance subject
	subject := &ita.ResourceDescriptor{
		Name:    "someVMInstance",
		Content: []byte("vmID"),
		Digest:  map[string]string{"alg": "5001ee7"},
	}

	// generate dummy SLSA provenance
	target := &ita.ResourceDescriptor{
		Name:      "dummy SLSA provenance",
		Digest:    map[string]string{"alg": "abc123"},
		MediaType: "application/vnd.in-toto.provenance+dsse",
	}

	st, err := internal.NewRefValueStatement([]*ita.ResourceDescriptor{subject}, "VM image", target, evidenceFile)
	if err != nil {
		return fmt.Errorf("error generating reference value: %w", err)
	}

	return fileio.WritePbToFile(st, outFile, prettyPrint)
}
