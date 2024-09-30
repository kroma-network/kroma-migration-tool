package main

import (
	"bytes"
	"context"
	"fmt"
	"math/big"
	"os"
	"path/filepath"

	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/trie/zk"
	"github.com/holiman/uint256"
	"golang.org/x/sync/errgroup"
)

const (
	NumProcessAccount = 16
	NumProcessStorage = 16
)

var allocPreimage map[common.Hash][]byte

func init() {
	defaultTerminalHandler := log.NewTerminalHandler(os.Stderr, false)
	glogger := log.NewGlogHandler(defaultTerminalHandler)
	glogger.Verbosity(log.LvlTrace)
	log.SetDefault(log.NewLogger(glogger))
}

func openDatabase() (ethdb.Database, error) {
	return rawdb.Open(rawdb.OpenOptions{
		Type: "pebble",
		// Directory: filepath.Join("/var/lib/docker/volumes/kroma-up_db-sepolia/_data/geth/chaindata"),
		Directory: filepath.Join("/var/lib/docker/volumes/kroma-up_db-mainnet/_data/geth/chaindata"),
		Namespace: "",
		Cache:     512,
		Handles:   utils.MakeDatabaseHandles(0),
		ReadOnly:  false,
	})
}

func loadZkPreimageWithAlloc(db ethdb.Database) error {
	genesis, err := core.ReadGenesis(db)
	if err != nil {
		return fmt.Errorf("failed to load genesis from database: %w", err)
	}
	preimages := make(map[common.Hash][]byte)
	for addr, account := range genesis.Alloc {
		hash := common.BytesToHash(zk.MustNewSecureHash(addr.Bytes()).Bytes())
		preimages[hash] = addr.Bytes()

		if account.Storage != nil {
			for key := range account.Storage {
				hash = common.BytesToHash(zk.MustNewSecureHash(key.Bytes()).Bytes())
				preimages[hash] = key.Bytes()
			}
		}
	}

	slots := []string{
		"0x0000000000000000000000000000000000000000000000000000000000000000",
		"0x0000000000000000000000000000000000000000000000000000000000000001",
		"0x0000000000000000000000000000000000000000000000000000000000000002",
		"0x0000000000000000000000000000000000000000000000000000000000000003",
		"0x0000000000000000000000000000000000000000000000000000000000000004",
		"0x0000000000000000000000000000000000000000000000000000000000000005",
		"0x0000000000000000000000000000000000000000000000000000000000000006",
		"0x0000000000000000000000000000000000000000000000000000000000000007",
		"0x0000000000000000000000000000000000000000000000000000000000000066",
		"0x0000000000000000000000000000000000000000000000000000000000000067",
		"0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6",
		"0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf7",
		"0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf8",
		"0x21274e0784154966da0827c4d8ff52398da1ffd72d4fd4ce3bba770ef4f51046",
		"0x5acfd26b00a93d43fa7675595844d651448f11c518e88b56112d82b524be63d1",
		"0xacc99a53bbce4565f990e4e6dc196b13bdfa596d74000f1b419d698c1357e761",
		"0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103",
	}
	for _, slot := range slots {
		hash := common.BytesToHash(zk.MustNewSecureHash(common.HexToHash(slot).Bytes()).Bytes())
		preimages[hash] = common.HexToHash(slot).Bytes()
	}

	allocPreimage = preimages
	return nil
}

func readZkPreimage(zkdb *trie.Database, key []byte) []byte {
	if allocPreimage == nil {
		panic("init preimage first")
	}
	hk := *trie.IteratorKeyToHash(key, true)
	if preimage, ok := allocPreimage[hk]; ok {
		return preimage
	}
	if preimage := zkdb.Preimage(hk); preimage != nil {
		if common.BytesToHash(zk.MustNewSecureHash(preimage).Bytes()).Hex() == hk.Hex() {
			return preimage
		}
	}
	log.Error("Preimage does not exist", "hashKey", hk.Hex())
	panic("preimage not exist")
}

var hashSpace = new(big.Int).Exp(common.Big2, common.Big256, nil)

// hashRange is a utility to handle ranges of hashes, Split up the
// hash-space into sections, and 'walk' over the sections
type hashRange struct {
	current *uint256.Int
	step    *uint256.Int
}

// newHashRange creates a new hashRange, initiated at the start position,
// and with the step set to fill the desired 'num' chunks
func newHashRange(start common.Hash, num uint64) *hashRange {
	left := new(big.Int).Sub(hashSpace, start.Big())
	step := new(big.Int).Div(
		new(big.Int).Add(left, new(big.Int).SetUint64(num-1)),
		new(big.Int).SetUint64(num),
	)
	step256 := new(uint256.Int)
	step256.SetFromBig(step)

	return &hashRange{
		current: new(uint256.Int).SetBytes32(start[:]),
		step:    step256,
	}
}

// Next pushes the hash range to the next interval.
func (r *hashRange) Next() bool {
	if r.step.IsZero() {
		return false
	}
	next, overflow := new(uint256.Int).AddOverflow(r.current, r.step)
	if overflow {
		return false
	}
	r.current = next
	return true
}

// Start returns the first hash in the current interval.
func (r *hashRange) Start() common.Hash {
	return r.current.Bytes32()
}

// End returns the last hash in the current interval.
func (r *hashRange) End() common.Hash {
	// If the end overflows (non divisible range), return a shorter interval
	next, overflow := new(uint256.Int).AddOverflow(r.current, r.step)
	if overflow {
		return common.MaxHash
	}
	return next.SubUint64(next, 1).Bytes32()
}

// hashRangeIterator
func hashRangeIterator(tr state.Trie, num uint64, onLeaf func(key, value []byte) error) error {
	r := newHashRange(common.Hash{}, num)

	eg, _ := errgroup.WithContext(context.Background())
	for {
		startKey := r.Start().Bytes()
		endKey := r.End().Bytes()

		eg.Go(func() error {
			nodeIt, err := tr.NodeIterator(startKey)
			if err != nil {
				log.Error("Failed to open node iterator", "root", tr.Hash(), "err", err)
				return err
			}
			iter := trie.NewIterator(nodeIt)
			for iter.Next() {
				if bytes.Compare(iter.Key, startKey) == -1 {
					continue
				}
				if bytes.Compare(iter.Key, endKey) == 1 {
					break
				}
				if err := onLeaf(iter.Key, iter.Value); err != nil {
					return err
				}
				if bytes.Compare(iter.Key, endKey) == 0 {
					break
				}
			}
			if iter.Err != nil {
				log.Error("Failed to traverse state trie", "root", tr.Hash(), "err", iter.Err)
				return err
			}
			return nil
		})

		if !r.Next() {
			break
		}
	}
	if err := eg.Wait(); err != nil {
		return err
	}
	return nil
}

func noErr(err error) {
	if err != nil {
		panic(err)
	}
}
