package main

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/trie/trienode"
	"github.com/ethereum/go-ethereum/trie/zk"
)

type StateMigrator struct {
	db            ethdb.Database
	zkdb          *trie.Database
	mptdb         *trie.Database
	allocPreimage map[common.Hash][]byte
	migratedRef   *core.MigratedRef

	stopCh chan struct{}

	accountCnt atomic.Uint64
	storageCnt atomic.Uint64
}

func StartMigration() {
	db, err := openDatabase()
	noErr(err)

	err = loadZkPreimageWithAlloc(db)
	noErr(err)

	m := &StateMigrator{
		db:      db,
		zkdb: trie.NewDatabase(db, &trie.Config{
			Preimages:   true,
			Zktrie:      true,
			KromaZKTrie: false,
		}),
		mptdb:         trie.NewDatabase(db, &trie.Config{Preimages: true}),
		allocPreimage: allocPreimage,
		migratedRef:   core.NewMigratedRef(db),
		stopCh:        make(chan struct{}),
	}

	log.Info("Starting state migrator to migrate ZKT to MPT")
	header := rawdb.ReadHeadHeader(m.db)
	if m.migratedRef.BlockNumber() != 0 {
		err := m.migratedRef.Update(common.Hash{}, 0)
		noErr(err)
	}
	log.Info("Start migrate past states")
	root, blockNumber, err := m.migrateAccount(header)
	noErr(err)
	err = m.migratedRef.Update(root, blockNumber)
	noErr(err)
}

func (m *StateMigrator) migrateAccount(header *types.Header) (common.Hash, uint64, error) {
	log.Info("Migrate account", "root", header.Root, "number", header.Number)
	startAt := time.Now()
	var accounts atomic.Uint64

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		ticker := time.NewTicker(time.Minute)
		for {
			select {
			case <-ticker.C:
				log.Info("Migrate accounts in progress", "accounts", accounts.Load())
			case <-ctx.Done():
				return
			}
		}
	}()

	mpt, err := trie.NewStateTrie(trie.TrieID(types.EmptyRootHash), m.mptdb)
	if err != nil {
		return common.Hash{}, 0, err
	}

	zkt, err := trie.NewZkMerkleStateTrie(header.Root, m.zkdb)
	if err != nil {
		return common.Hash{}, 0, err
	}
	var mu sync.Mutex
	err = hashRangeIterator(zkt, NumProcessAccount, func(key, value []byte) error {
		m.accountCnt.Add(1)
		accounts.Add(1)
		address := common.BytesToAddress(m.readZkPreimage(key))
		log.Info("Start migrate account", "address", address.Hex())
		acc, err := types.NewStateAccount(value, true)
		if err != nil {
			return err
		}
		acc.Root, err = m.migrateStorage(address, acc.Root)
		if err != nil {
			return err
		}
		mu.Lock()
		defer mu.Unlock()
		if err := mpt.UpdateAccount(address, acc); err != nil {
			return err
		}

		log.Trace("Account updated in MPT", "account", address.Hex(), "index", common.BytesToHash(key).Hex())
		return nil
	})
	noErr(err)

	root, err := m.commit(mpt, types.EmptyRootHash)
	noErr(err)
	log.Info("Account migration finished", "accounts", accounts.Load(), "storages", m.storageCnt.Load(), "elapsed", time.Since(startAt))
	return root, header.Number.Uint64(), nil
}

func (m *StateMigrator) migrateStorage(
	address common.Address,
	zkStorageRoot common.Hash,
) (common.Hash, error) {
	startAt := time.Now()
	log.Debug("Start migrate storage", "address", address.Hex())
	if zkStorageRoot == (common.Hash{}) {
		return types.EmptyRootHash, nil
	}

	id := trie.StorageTrieID(types.EmptyRootHash, crypto.Keccak256Hash(address.Bytes()), types.EmptyRootHash)
	mpt, err := trie.NewStateTrie(id, m.mptdb)
	if err != nil {
		return common.Hash{}, err
	}

	zkt, err := trie.NewZkMerkleStateTrie(zkStorageRoot, m.zkdb)
	if err != nil {
		return common.Hash{}, err
	}

	var mu sync.Mutex
	var slots atomic.Uint64

	err = hashRangeIterator(zkt, NumProcessStorage, func(key, value []byte) error {
		mu.Lock()
		defer mu.Unlock()
		m.storageCnt.Add(1)
		slots.Add(1)
		slot := m.readZkPreimage(key)
		trimmed := common.TrimLeftZeroes(common.BytesToHash(value).Bytes())
		if err := mpt.UpdateStorage(address, slot, trimmed); err != nil {
			return err
		}
		log.Trace("Updated storage slot to MPT", "contract", address.Hex(), "index", common.BytesToHash(key).Hex())
		return nil
	})
	noErr(err)

	root, err := m.commit(mpt, types.EmptyRootHash)
	noErr(err)
	log.Debug("Storage migration finished", "account", address, "slots", slots.Load(), "elapsed", time.Since(startAt))

	return root, nil
}
func (m *StateMigrator) readZkPreimage(key []byte) []byte {
	hk := *trie.IteratorKeyToHash(key, true)
	if preimage, ok := m.allocPreimage[hk]; ok {
		return preimage
	}
	if preimage := m.zkdb.Preimage(hk); preimage != nil {
		if common.BytesToHash(zk.MustNewSecureHash(preimage).Bytes()).Hex() == hk.Hex() {
			return preimage
		}
	}
	log.Crit("Preimage does not exist", "hashKey", hk.Hex())
	return []byte{}
}

func (m *StateMigrator) commit(mpt *trie.StateTrie, parentHash common.Hash) (common.Hash, error) {
	root, set, err := mpt.Commit(true)
	if err != nil {
		return common.Hash{}, err
	}
	if set == nil {
		log.Warn("Tried to commit state changes, but nothing has changed.", "root", root)
		return root, nil
	}

	var hashCollidedErr error
	set.ForEachWithOrder(func(path string, n *trienode.Node) {
		if hashCollidedErr != nil {
			return
		}
		// NOTE(pangssu): It is possible that the keccak256 and poseidon hashes collide, and data loss can occur.
		data, _ := m.db.Get(n.Hash.Bytes())
		if len(data) == 0 {
			return
		}
		if node, err := zk.NewTreeNodeFromBlob(data); err == nil {
			hashCollidedErr = fmt.Errorf("hash collision detected: hashKey: %v, key: %v, value: %v, zkNode: %v", n.Hash.Bytes(), path, data, node)
		}
	})
	if hashCollidedErr != nil {
		return common.Hash{}, hashCollidedErr
	}

	if err := m.mptdb.Update(root, parentHash, 0, trienode.NewWithNodeSet(set), nil); err != nil {
		return common.Hash{}, err
	}
	if err := m.mptdb.Commit(root, false); err != nil {
		return common.Hash{}, err
	}
	return root, nil
}
