package main

import (
	"bytes"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
)

func StartValidation() {
	db, err := openDatabase()
	noErr(err)

	err = loadZkPreimageWithAlloc(db)
	noErr(err)

	migrationRef := core.NewMigratedRef(db)
	fmt.Println("migration ref:", migrationRef.BlockNumber(), migrationRef.Root())
	zkBlockHash := rawdb.ReadCanonicalHash(db, migrationRef.BlockNumber())
	zkBlock := rawdb.ReadBlock(db, zkBlockHash, migrationRef.BlockNumber())
	fmt.Println("zk block number", zkBlock.Number(), zkBlockHash, zkBlock.Root())

	zkdb := trie.NewDatabase(db, &trie.Config{
		Preimages:   true,
		Zktrie:      true,
		KromaZKTrie: false,
	})
	mptdb := trie.NewDatabase(db, &trie.Config{
		Preimages: true,
	})

	var zkAccountCnt atomic.Uint64
	var zkStorageCnt atomic.Uint64
	var mptAccountCnt atomic.Uint64
	var mptStorageCnt atomic.Uint64
	var zkCodeCnt atomic.Uint64
	var mptCodeCnt atomic.Uint64
	var zkNonce atomic.Uint64
	var mptNonce atomic.Uint64
	var zkBalance atomic.Uint64
	var mptBalance atomic.Uint64

	var wg sync.WaitGroup

	wg.Add(2)

	startAt := time.Now()
	go func() {
		zktr, err := trie.NewZkMerkleStateTrie(zkBlock.Root(), zkdb)
		noErr(err)
		mptr, err := trie.NewStateTrie(trie.StateTrieID(migrationRef.Root()), mptdb)
		noErr(err)

		var mu sync.Mutex
		err = hashRangeIterator(zktr, NumProcessAccount, func(key, value []byte) error {
			zkAccountCnt.Add(1)
			zktAcc, err := types.NewStateAccount(value, true)
			noErr(err)

			addr := common.BytesToAddress(readZkPreimage(zkdb, key))

			mu.Lock()
			mptAcc, err := mptr.GetAccount(addr)
			noErr(err)
			mu.Unlock()

			if zktAcc.Balance.Cmp(mptAcc.Balance) != 0 {
				log.Error("balance diff", "addr", addr, "zkt", zktAcc.Balance, "mpt", mptAcc.Balance)
				panic("validation failed")
			}
			if zktAcc.Nonce != mptAcc.Nonce {
				log.Error("nonce diff", "addr", addr, "zkt", zktAcc.Nonce, "mpt", mptAcc.Nonce)
				panic("validation failed")
			}
			if !bytes.Equal(zktAcc.CodeHash, mptAcc.CodeHash) {
				log.Error("codeHash diff", "addr", addr, "zkt", zktAcc.CodeHash, "mpt", mptAcc.CodeHash)
				panic("validation failed")
			}
			if !bytes.Equal(zktAcc.CodeHash, types.EmptyCodeHash.Bytes()) && !rawdb.HasCode(db, common.BytesToHash(zktAcc.CodeHash)) {
				log.Error("Code is missing", "addr", addr, "hash", common.BytesToHash(zktAcc.CodeHash))
				panic("validation failed")
			} else {
				zkCodeCnt.Add(1)
			}

			zkBalance.Add(zktAcc.Balance.Uint64())
			zkNonce.Add(zktAcc.Nonce)

			if zktAcc.Root != (common.Hash{}) {
				zktr, err := trie.NewZkMerkleStateTrie(zktAcc.Root, zkdb)
				noErr(err)
				mptr, err := trie.NewStateTrie(trie.StorageTrieID(migrationRef.Root(), crypto.Keccak256Hash(addr[:]), mptAcc.Root), mptdb)
				noErr(err)

				var mu sync.Mutex
				err = hashRangeIterator(zktr, NumProcessStorage, func(key, value []byte) error {
					mu.Lock()
					defer mu.Unlock()

					zkStorageCnt.Add(1)
					slot := readZkPreimage(zkdb, key)
					trimmed := common.TrimLeftZeroes(common.BytesToHash(value).Bytes())
					mptVal, err := mptr.GetStorage(addr, slot)
					noErr(err)

					if !bytes.Equal(trimmed, mptVal) {
						log.Error("storage value diff", "addr", addr, "slot", common.BytesToHash(slot), "zkt", common.BytesToHash(trimmed), "mpt", common.BytesToHash(mptVal))
						panic("validation failed")
					}

					return nil
				})
				noErr(err)
			}
			return nil
		})
		noErr(err)
		wg.Done()
	}()

	go func() {
		zktr, err := trie.NewZkMerkleStateTrie(zkBlock.Root(), zkdb)
		noErr(err)
		mptr, err := trie.NewStateTrie(trie.StateTrieID(migrationRef.Root()), mptdb)
		noErr(err)

		var mu sync.Mutex
		err = hashRangeIterator(mptr, NumProcessAccount, func(key, value []byte) error {
			mptAccountCnt.Add(1)
			var mptAcc types.StateAccount
			err := rlp.DecodeBytes(value, &mptAcc)
			noErr(err)

			addr := common.BytesToAddress(mptdb.Preimage(common.BytesToHash(key)))
			mu.Lock()
			zktAcc, err := zktr.GetAccount(addr)
			noErr(err)
			mu.Unlock()

			if zktAcc.Balance.Cmp(mptAcc.Balance) != 0 {
				log.Error("balance diff", "addr", addr, "mpt", mptAcc.Balance, "zkt", zktAcc.Balance)
				panic("validation failed")
			}
			if zktAcc.Nonce != mptAcc.Nonce {
				log.Error("nonce diff", "addr", addr, "mpt", mptAcc.Nonce, "zkt", zktAcc.Nonce)
				panic("validation failed")
			}
			if !bytes.Equal(zktAcc.CodeHash, mptAcc.CodeHash) {
				log.Error("codeHash diff", "addr", addr, "mpt", mptAcc.CodeHash, "zkt", zktAcc.CodeHash)
				panic("validation failed")
			}
			if !bytes.Equal(zktAcc.CodeHash, types.EmptyCodeHash.Bytes()) && !rawdb.HasCode(db, common.BytesToHash(zktAcc.CodeHash)) {
				log.Error("Code is missing", "addr", addr, "hash", common.BytesToHash(zktAcc.CodeHash))
				panic("validation failed")
			} else {
				mptCodeCnt.Add(1)
			}

			mptBalance.Add(mptAcc.Balance.Uint64())
			mptNonce.Add(mptAcc.Nonce)

			if mptAcc.Root != types.EmptyRootHash {
				zktr, err := trie.NewZkMerkleStateTrie(zktAcc.Root, zkdb)
				noErr(err)
				mptr, err := trie.NewStateTrie(trie.StorageTrieID(migrationRef.Root(), crypto.Keccak256Hash(addr[:]), mptAcc.Root), mptdb)
				noErr(err)

				var mu sync.Mutex
				err = hashRangeIterator(mptr, NumProcessStorage, func(key, value []byte) error {
					mu.Lock()
					defer mu.Unlock()

					mptStorageCnt.Add(1)
					slot := mptdb.Preimage(common.BytesToHash(key))
					_, content, _, err := rlp.Split(value)
					noErr(err)
					zeroFilled := common.BytesToHash(content).Bytes()

					zktVal, err := zktr.GetStorage(addr, slot)
					noErr(err)

					if !bytes.Equal(zeroFilled, zktVal) {
						log.Error("storage value diff", "addr", addr, "slot", common.BytesToHash(slot), "mpt", common.BytesToHash(zeroFilled), "zkt", common.BytesToHash(zktVal))
						fmt.Println(common.Bytes2Hex(zeroFilled))
						fmt.Println(common.Bytes2Hex(zktVal))
						panic("validation failed")
					}

					return nil
				})
				noErr(err)
			}
			return nil
		})
		noErr(err)
		wg.Done()
	}()

	wg.Wait()

	fmt.Println("zkAccountCnt", zkAccountCnt.Load())
	fmt.Println("mptAccountCnt", mptAccountCnt.Load())
	if zkAccountCnt.Load() != mptAccountCnt.Load() {
		fmt.Println("  - INVALID account state trie leaves")
	}
	fmt.Println("zkStorageCnt", zkStorageCnt.Load())
	fmt.Println("mptStorageCnt", mptStorageCnt.Load())
	if zkStorageCnt.Load() != mptStorageCnt.Load() {
		fmt.Println("  - INVALID storage trie leaves")
	}
	fmt.Println("zkCodeCnt", zkCodeCnt.Load())
	fmt.Println("mptCodeCnt", mptCodeCnt.Load())
	if zkCodeCnt.Load() != mptCodeCnt.Load() {
		fmt.Println("  - INVALID code count")
	}
	fmt.Println("zkBalance", zkBalance.Load())
	fmt.Println("mptBalance", mptBalance.Load())
	if zkBalance.Load() != mptBalance.Load() {
		fmt.Println("  - INVALID balance")
	}
	fmt.Println("zkNonce", zkNonce.Load())
	fmt.Println("mptNonce", mptNonce.Load())
	if zkNonce.Load() != mptNonce.Load() {
		fmt.Println("  - INVALID nonce")
	}

	log.Info("finished", "elapsed", time.Since(startAt))
}
