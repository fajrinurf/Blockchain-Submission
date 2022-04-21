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
// Anda seharusnya telah menerima salinan GNU Lesser General Public License
// bersama dengan perpustakaan go-ethereum. Jika tidak, lihat <http://www.gnu.org/licenses/>.

package beacon

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/trie"
)

// Konstanta protokol proof-of-stake.
var (
	beaconDifficulty = common.Big0          // Kesulitan blok default dalam konsensus suar
	beaconNonce      = types.EncodeNonce(0) // Blok default nonce dalam konsensus suar
)

// Berbagai pesan kesalahan untuk menandai blok tidak valid. Ini harus bersifat pribadi untuk
// mencegah kesalahan khusus mesin agar tidak direferensikan di sisa
// basis kode, secara inheren rusak jika mesin ditukar. Tolong cantumkan umum
// jenis kesalahan ke dalam paket konsensus.
var (
	errTooManyUncles    = errors.New("too many uncles")
	errInvalidNonce     = errors.New("invalid nonce")
	errInvalidUncleHash = errors.New("invalid uncle hash")
)

// Beacon adalah mesin konsensus yang menggabungkan konsensus eth1 dan bukti kepemilikan
// algoritma. Ada bendera khusus di dalamnya untuk memutuskan apakah akan menggunakan konsensus warisan
// aturan atau aturan baru. Aturan transisi dijelaskan dalam spesifikasi gabungan eth1/2.
// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-3675.md
//
// Beacon di sini adalah mesin konsensus setengah fungsi dengan fungsi parsial yang
// hanya digunakan untuk pemeriksaan konsensus yang diperlukan. Mesin konsensus warisan dapat berupa apa saja
// engine mengimplementasikan antarmuka konsensus (kecuali suar itu sendiri).
type Beacon struct {
	ethone consensus.Engine // Mesin konsensus asli yang digunakan di eth1, mis. etash atau klik
}

// New membuat mesin konsensus dengan mesin eth1 tertanam yang diberikan.
func New(ethone consensus.Engine) *Beacon {
	if _, ok := ethone.(*Beacon); ok {
		panic("nested consensus engine")
	}
	return &Beacon{ethone: ethone}
}

// Penulis mengimplementasikan konsensus.Mesin, mengembalikan pembuat blok yang diverifikasi.
func (beacon *Beacon) Author(header *types.Header) (common.Address, error) {
	if !beacon.IsPoSHeader(header) {
		return beacon.ethone.Author(header)
	}
	return header.Coinbase, nil
}

// VerifyHeader memeriksa apakah header sesuai dengan aturan konsensus dari
// stok mesin konsensus Ethereum.
func (beacon *Beacon) VerifyHeader(chain consensus.ChainHeaderReader, header *types.Header, seal bool) error {
	reached, _ := IsTTDReached(chain, header.ParentHash, header.Number.Uint64()-1)
	if !reached {
		return beacon.ethone.VerifyHeader(chain, header, seal)
	}
	// Hubungan pendek jika induknya tidak diketahui
	parent := chain.GetHeader(header.ParentHash, header.Number.Uint64()-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	// Pemeriksaan kewarasan lulus, lakukan verifikasi yang tepat
	return beacon.verifyHeader(chain, header, parent)
}

// VerifyHeaders mirip dengan VerifyHeader, tetapi memverifikasi sekumpulan header
// bersamaan. Metode mengembalikan saluran keluar untuk membatalkan operasi dan
// saluran hasil untuk mengambil verifikasi asinkron.
// VerifyHeaders mengharapkan header untuk diurutkan dan berkelanjutan.
func (beacon *Beacon) VerifyHeaders(chain consensus.ChainHeaderReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	if !beacon.IsPoSHeader(headers[len(headers)-1]) {
		return beacon.ethone.VerifyHeaders(chain, headers, seals)
	}
	var (
		preHeaders  []*types.Header
		postHeaders []*types.Header
		preSeals    []bool
	)
	for index, header := range headers {
		if beacon.IsPoSHeader(header) {
			preHeaders = headers[:index]
			postHeaders = headers[index:]
			preSeals = seals[:index]
			break
		}
	}
	// Semua header telah melewati titik transisi, gunakan aturan baru.
	if len(preHeaders) == 0 {
		return beacon.verifyHeaders(chain, headers, nil)
	}
	// Titik transisi ada di tengah, pisahkan header
	// menjadi dua kelompok dan menerapkan aturan verifikasi yang berbeda untuk mereka.
	var (
		abort   = make(chan struct{})
		results = make(chan error, len(headers))
	)
	go func() {
		var (
			old, new, out      = 0, len(preHeaders), 0
			errors             = make([]error, len(headers))
			done               = make([]bool, len(headers))
			oldDone, oldResult = beacon.ethone.VerifyHeaders(chain, preHeaders, preSeals)
			newDone, newResult = beacon.verifyHeaders(chain, postHeaders, preHeaders[len(preHeaders)-1])
		)
		for {
			for ; done[out]; out++ {
				results <- errors[out]
				if out == len(headers)-1 {
					return
				}
			}
			select {
			case err := <-oldResult:
				errors[old], done[old] = err, true
				old++
			case err := <-newResult:
				errors[new], done[new] = err, true
				new++
			case <-abort:
				close(oldDone)
				close(newDone)
				return
			}
		}
	}()
	return abort, results
}

// Verifikasi Paman memverifikasi bahwa blok yang diberikan paman sesuai dengan konsensus
// aturan mesin konsensus Ethereum.
func (beacon *Beacon) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	if !beacon.IsPoSHeader(block.Header()) {
		return beacon.ethone.VerifyUncles(chain, block)
	}
	// Verifikasi bahwa tidak ada blok paman. Ini secara eksplisit dinonaktifkan di suar
	if len(block.Uncles()) > 0 {
		return errTooManyUncles
	}
	return nil
}

// verifikasiHeader memeriksa apakah header sesuai dengan aturan konsensus dari
// stok mesin konsensus Ethereum. Perbedaan antara suar dan klasik adalah
// (a) Bidang berikut diharapkan menjadi konstanta:
// - kesulitan diperkirakan 0
// - nonce diharapkan menjadi 0
// - pamanhash diharapkan menjadi Hash(emptyHeader)
// menjadi konstanta yang diinginkan
// (b) stempel waktu tidak diverifikasi lagi
// (c) ekstradata dibatasi hingga 32 byte
func (beacon *Beacon) verifyHeader(chain consensus.ChainHeaderReader, header, parent *types.Header) error {
	// Pastikan bagian data ekstra header memiliki ukuran yang wajar
	if len(header.Extra) > 32 {
		return fmt.Errorf("extra-data longer than 32 bytes (%d)", len(header.Extra))
	}
	// Verifikasi bagian segel. Pastikan hash nonce dan paman adalah nilai yang diharapkan.
	if header.Nonce != beaconNonce {
		return errInvalidNonce
	}
	if header.UncleHash != types.EmptyUncleHash {
		return errInvalidUncleHash
	}
	// Verifikasi tingkat kesulitan blok untuk memastikan itu adalah konstanta default
	if beaconDifficulty.Cmp(header.Difficulty) != 0 {
		return fmt.Errorf("invalid difficulty: have %v, want %v", header.Difficulty, beaconDifficulty)
	}
	// Pastikan batas gas <= 2^63-1
	if header.GasLimit > params.MaxGasLimit {
		return fmt.Errorf("invalid gasLimit: have %v, max %v", header.GasLimit, params.MaxGasLimit)
	}
	// Verifikasi bahwa gas yang digunakan adalah <= gasLimit
	if header.GasUsed > header.GasLimit {
		return fmt.Errorf("invalid gasUsed: have %d, gasLimit %d", header.GasUsed, header.GasLimit)
	}
	// Verifikasi bahwa nomor blok adalah +1 induknya
	if diff := new(big.Int).Sub(header.Number, parent.Number); diff.Cmp(common.Big1) != 0 {
		return consensus.ErrInvalidNumber
	}
	// Verifikasi atribut EIP-1559 header.
	return misc.VerifyEip1559Header(chain.Config(), parent, header)
}

// verifikasiHeaders mirip dengan verifikasiHeader, tetapi memverifikasi sekumpulan header
// bersamaan. Metode mengembalikan saluran keluar untuk membatalkan operasi dan
// saluran hasil untuk mengambil verifikasi asinkron. Orang tua tambahan
// header akan diteruskan jika header yang relevan belum ada di database.
func (beacon *Beacon) verifyHeaders(chain consensus.ChainHeaderReader, headers []*types.Header, ancestor *types.Header) (chan<- struct{}, <-chan error) {
	var (
		abort   = make(chan struct{})
		results = make(chan error, len(headers))
	)
	go func() {
		for i, header := range headers {
			var parent *types.Header
			if i == 0 {
				if ancestor != nil {
					parent = ancestor
				} else {
					parent = chain.GetHeader(headers[0].ParentHash, headers[0].Number.Uint64()-1)
				}
			} else if headers[i-1].Hash() == headers[i].ParentHash {
				parent = headers[i-1]
			}
			if parent == nil {
				select {
				case <-abort:
					return
				case results <- consensus.ErrUnknownAncestor:
				}
				continue
			}
			err := beacon.verifyHeader(chain, header, parent)
			select {
			case <-abort:
				return
			case results <- err:
			}
		}
	}()
	return abort, results
}

// Siapkan implementasi konsensus.Mesin, menginisialisasi bidang kesulitan a
// header agar sesuai dengan protokol beacon. Perubahan dilakukan secara inline.
func (beacon *Beacon) Prepare(chain consensus.ChainHeaderReader, header *types.Header) error {
	// Transisi belum dipicu, gunakan aturan lama untuk persiapan.
	reached, err := IsTTDReached(chain, header.ParentHash, header.Number.Uint64()-1)
	if err != nil {
		return err
	}
	if !reached {
		return beacon.ethone.Prepare(chain, header)
	}
	header.Difficulty = beaconDifficulty
	return nil
}

// Finalize mengimplementasikan konsensus.Mesin, mengatur status akhir pada header
func (beacon *Beacon) Finalize(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header) {
	// Finalisasi berbeda dengan Siapkan, dapat digunakan di kedua pembuatan blok
	// dan verifikasi. Jadi tentukan aturan konsensus berdasarkan jenis header.
	if !beacon.IsPoSHeader(header) {
		beacon.ethone.Finalize(chain, header, state, txs, uncles)
		return
	}
	// Hadiah blok tidak lagi ditangani di sini. Itu dilakukan oleh
	// mesin konsensus eksternal.
	header.Root = state.IntermediateRoot(true)
}

// FinalizeAndAssemble mengimplementasikan konsensus.Mesin, menyetel status akhir dan
// merakit blok.
func (beacon *Beacon) FinalizeAndAssemble(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header, receipts []*types.Receipt) (*types.Block, error) {
	// FinalizeAndAssemble berbeda dengan Prepare, dapat digunakan di kedua blok
	// pembuatan dan verifikasi. Jadi tentukan aturan konsensus berdasarkan jenis header.
	if !beacon.IsPoSHeader(header) {
		return beacon.ethone.FinalizeAndAssemble(chain, header, state, txs, uncles, receipts)
	}
	// Menyelesaikan dan merakit blok
	beacon.Finalize(chain, header, state, txs, uncles)
	return types.NewBlock(header, txs, uncles, receipts, trie.NewStackTrie(nil)), nil
}

// Seal menghasilkan permintaan penyegelan baru untuk blok input yang diberikan dan mendorong
// hasilnya ke saluran yang diberikan.
//
// Catatan, metode ini segera kembali dan akan mengirimkan hasil async. Lagi
// dari satu hasil juga dapat dikembalikan tergantung pada algoritma konsensus.
func (beacon *Beacon) Seal(chain consensus.ChainHeaderReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}) error {
	if !beacon.IsPoSHeader(block.Header()) {
		return beacon.ethone.Seal(chain, block, results, stop)
	}
	// Verifikasi segel dilakukan oleh mesin konsensus eksternal,
	// kembali langsung tanpa mendorong blok apa pun ke belakang. Dengan kata lain
	// beacon tidak akan mengembalikan hasil apa pun melalui saluran `results` yang mungkin
	// memblokir logika penerima selamanya.
	return nil
}

// SealHash mengembalikan hash dari sebuah blok sebelum disegel.
func (beacon *Beacon) SealHash(header *types.Header) common.Hash {
	return beacon.ethone.SealHash(header)
}

// CalcDifficulty adalah algoritma penyesuaian kesulitan. Ini kembali
// kesulitan yang harus dimiliki blok baru saat dibuat pada waktunya
// mengingat waktu dan kesulitan blok induk.
func (beacon *Beacon) CalcDifficulty(chain consensus.ChainHeaderReader, time uint64, parent *types.Header) *big.Int {
	// Transisi belum dipicu, gunakan aturan lama untuk perhitungan
	if reached, _ := IsTTDReached(chain, parent.Hash(), parent.Number.Uint64()); !reached {
		return beacon.ethone.CalcDifficulty(chain, time, parent)
	}
	return beaconDifficulty
}

// API mengimplementasikan konsensus.Mesin, mengembalikan pengguna yang menghadapi API RPC.
func (beacon *Beacon) APIs(chain consensus.ChainHeaderReader) []rpc.API {
	return beacon.ethone.APIs(chain)
}

// Tutup mematikan mesin konsensus
func (beacon *Beacon) Close() error {
	return beacon.ethone.Close()
}

// IsPoSHeader melaporkan header milik tahap PoS dengan beberapa bidang khusus.
// Fungsi ini tidak cocok untuk bagian API seperti Siapkan atau CalcDifficulty
// karena tingkat kesulitan header belum disetel.
func (beacon *Beacon) IsPoSHeader(header *types.Header) bool {
	if header.Difficulty == nil {
		panic("IsPoSHeader called with invalid difficulty")
	}
	return header.Difficulty.Cmp(beaconDifficulty) == 0
}

// InnerEngine mengembalikan mesin konsensus eth1 yang disematkan.
func (beacon *Beacon) InnerEngine() consensus.Engine {
	return beacon.ethone
}

// SetThreads memperbarui utas penambangan. Delegasikan panggilan
// ke mesin eth1 jika di-thread.
func (beacon *Beacon) SetThreads(threads int) {
	type threaded interface {
		SetThreads(threads int)
	}
	if th, ok := beacon.ethone.(threaded); ok {
		th.SetThreads(threads)
	}
}

// IsTTDReached memeriksa apakah TotalTerminalDifficulty telah dilampaui pada blok `parentHash`.
// Itu tergantung pada parentHash yang sudah disimpan dalam database.
// Jika parentHash tidak disimpan dalam database, kesalahan UnknownAncestor dikembalikan.
func IsTTDReached(chain consensus.ChainHeaderReader, parentHash common.Hash, number uint64) (bool, error) {
	if chain.Config().TerminalTotalDifficulty == nil {
		return false, nil
	}
	td := chain.GetTd(parentHash, number)
	if td == nil {
		return false, consensus.ErrUnknownAncestor
	}
	return td.Cmp(chain.Config().TerminalTotalDifficulty) >= 0, nil
}
