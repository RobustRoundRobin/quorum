package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/rororo"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"gopkg.in/urfave/cli.v1"
)

var (
	// Git information set by linker when building with ci.go.
	gitCommit string
	gitDate   string
	app       = &cli.App{
		Name:        filepath.Base(os.Args[0]),
		Usage:       "go-ethereum rororo tool",
		Version:     params.VersionWithCommit(gitCommit, gitDate),
		Writer:      os.Stdout,
		HideVersion: true,
	}
)

func init() {
	// Set up the CLI app.

	app.CommandNotFound = func(ctx *cli.Context, cmd string) {
		fmt.Fprintf(os.Stderr, "No such command: %s\n", cmd)
		os.Exit(1)
	}

	// Add subcommands.
	app.Commands = []cli.Command{
		genesisExtraCommand,
	}
}

var genesisExtraCommand = cli.Command{
	Name:   "genextra",
	Usage:  "Extra data for genesis document",
	Action: genextra,
	Flags: []cli.Flag{
		cli.StringFlag{Name: "datadir"},
		cli.StringFlag{Name: "key", Value: "key", Usage: "private key for the chain creator node (Ck)"},
	},
}

func readNodesJSON(path string) ([]*enode.Node, error) {
	// Load the nodes from the config file.
	var nodelist []string
	if err := common.LoadJSON(path, &nodelist); err != nil {
		return nil, fmt.Errorf("Can't load node list file: %v", err)
	}
	// Interpret the list as a discovery node array
	var nodes []*enode.Node
	for _, url := range nodelist {
		if url == "" {
			continue
		}
		node, err := enode.Parse(enode.ValidSchemes, url)
		if err != nil {
			return nil, fmt.Errorf("Node URL %s: %v\n", url, err)
		}
		nodes = append(nodes, node)
	}
	return nodes, nil
}

func resolvePath(dataDir, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	if dataDir != "" {
		return filepath.Join(dataDir, path)
	}
	return path
}

func genextra(ctx *cli.Context) error {

	dataDir := ctx.String("datadir")
	path := "static-nodes.json"
	if ctx.NArg() > 0 {
		path = ctx.Args()[0]
	}
	staticNodesJson := resolvePath(dataDir, path)
	key, err := crypto.LoadECDSA(resolvePath(dataDir, ctx.String("key")))
	if err != nil {
		return err
	}

	enodes, err := readNodesJSON(staticNodesJson)
	if err != nil {
		return err
	}

	var initIdents []rororo.Enrolment

	for _, en := range enodes {
		if initIdents, err = rororo.IdentInit(key, initIdents, en.ID()); err != nil {
			return err
		}
	}

	extra := &rororo.GenesisExtraData{}
	seed := make([]byte, 32)
	var nrand int
	nrand, err = rand.Read(seed)
	if err != nil || nrand != 32 {
		return fmt.Errorf("failed reading random seed")
	}

	if err = extra.ChainInit.Populate(key, initIdents, seed); err != nil {
		return err
	}

	var b []byte
	if b, err = rlp.EncodeToBytes(extra); err != nil {
		return err
	}
	fmt.Println(hex.EncodeToString(b))
	return nil
}

func main() {
	exit(app.Run(os.Args))
}

func exit(err interface{}) {
	if err == nil {
		os.Exit(0)
	}
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
