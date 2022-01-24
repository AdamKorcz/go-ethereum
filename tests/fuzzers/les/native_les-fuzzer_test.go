// Copyright 2021 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package les

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	l "github.com/ethereum/go-ethereum/les"
)




func FuzzLesNative(f *testing.F) {
	f.Fuzz(func(t *testing.T, input string) {
		// We expect some large inputs
		if len(input) < 100 {
			return
		}
		fz := newFuzzer(input)
		if fz.exhausted {
			return
		}
		for !fz.exhausted {
			switch fz.randomInt(8) {
			case 0:
				req := &l.GetBlockHeadersPacket{
					Query: l.GetBlockHeadersData{
						Amount:  fz.randomX(l.MaxHeaderFetch + 1),
						Skip:    fz.randomX(10),
						Reverse: fz.randomBool(),
					},
				}
				if fz.randomBool() {
					req.Query.Origin.Hash = fz.randomBlockHash()
				} else {
					req.Query.Origin.Number = uint64(fz.randomInt(fz.chainLen * 2))
				}
				fz.doFuzz(l.GetBlockHeadersMsg, req)

			case 1:
				req := &l.GetBlockBodiesPacket{Hashes: make([]common.Hash, fz.randomInt(l.MaxBodyFetch+1))}
				for i := range req.Hashes {
					req.Hashes[i] = fz.randomBlockHash()
				}
				fz.doFuzz(l.GetBlockBodiesMsg, req)

			case 2:
				req := &l.GetCodePacket{Reqs: make([]l.CodeReq, fz.randomInt(l.MaxCodeFetch+1))}
				for i := range req.Reqs {
					req.Reqs[i] = l.CodeReq{
						BHash:  fz.randomBlockHash(),
						AccKey: fz.randomAddrHash(),
					}
				}
				fz.doFuzz(l.GetCodeMsg, req)

			case 3:
				req := &l.GetReceiptsPacket{Hashes: make([]common.Hash, fz.randomInt(l.MaxReceiptFetch+1))}
				for i := range req.Hashes {
					req.Hashes[i] = fz.randomBlockHash()
				}
				fz.doFuzz(l.GetReceiptsMsg, req)

			case 4:
				req := &l.GetProofsPacket{Reqs: make([]l.ProofReq, fz.randomInt(l.MaxProofsFetch+1))}
				for i := range req.Reqs {
					if fz.randomBool() {
						req.Reqs[i] = l.ProofReq{
							BHash:     fz.randomBlockHash(),
							AccKey:    fz.randomAddrHash(),
							Key:       fz.randomAddrHash(),
							FromLevel: uint(fz.randomX(3)),
						}
					} else {
						req.Reqs[i] = l.ProofReq{
							BHash:     fz.randomBlockHash(),
							Key:       fz.randomAddrHash(),
							FromLevel: uint(fz.randomX(3)),
						}
					}
				}
				fz.doFuzz(l.GetProofsV2Msg, req)

			case 5:
				req := &l.GetHelperTrieProofsPacket{Reqs: make([]l.HelperTrieReq, fz.randomInt(l.MaxHelperTrieProofsFetch+1))}
				for i := range req.Reqs {
					switch fz.randomInt(3) {
					case 0:
						// Canonical hash trie
						req.Reqs[i] = l.HelperTrieReq{
							Type:      0,
							TrieIdx:   fz.randomX(3),
							Key:       fz.randomCHTTrieKey(),
							FromLevel: uint(fz.randomX(3)),
							AuxReq:    uint(2),
						}
					case 1:
						// Bloom trie
						req.Reqs[i] = l.HelperTrieReq{
							Type:      1,
							TrieIdx:   fz.randomX(3),
							Key:       fz.randomBloomTrieKey(),
							FromLevel: uint(fz.randomX(3)),
							AuxReq:    0,
						}
					default:
						// Random trie
						req.Reqs[i] = l.HelperTrieReq{
							Type:      2,
							TrieIdx:   fz.randomX(3),
							Key:       fz.randomCHTTrieKey(),
							FromLevel: uint(fz.randomX(3)),
							AuxReq:    0,
						}
					}
				}
				fz.doFuzz(l.GetHelperTrieProofsMsg, req)

			case 6:
				req := &l.SendTxPacket{Txs: make([]*types.Transaction, fz.randomInt(l.MaxTxSend+1))}
				signer := types.HomesteadSigner{}
				for i := range req.Txs {
					var nonce uint64
					if fz.randomBool() {
						nonce = uint64(fz.randomByte())
					} else {
						nonce = fz.nonce
						fz.nonce += 1
					}
					req.Txs[i], _ = types.SignTx(types.NewTransaction(nonce, common.Address{}, big.NewInt(10000), params.TxGas, big.NewInt(1000000000*int64(fz.randomByte())), nil), signer, bankKey)
				}
				fz.doFuzz(l.SendTxV2Msg, req)

			case 7:
				req := &l.GetTxStatusPacket{Hashes: make([]common.Hash, fz.randomInt(l.MaxTxStatus+1))}
				for i := range req.Hashes {
					req.Hashes[i] = fz.randomTxHash()
				}
				fz.doFuzz(l.GetTxStatusMsg, req)
			}
		}
		return
	})
}
