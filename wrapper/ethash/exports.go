// ProgPoW Ethash JSON wrapper
// Copyright (C) 2018  Antti Majakivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package ethash
import
(
    "hash"
)


// exports.go exports internal functions for external usage

func Export_cacheSize(block uint64) uint64 {
	return cacheSize(block)
}

func Export_datasetSize(block uint64) uint64 {
    return datasetSize(block)
}

func Export_seedHash(block uint64) []byte {
    //block number is epoch number when epochLength = 1  (algorithm.go)
    return seedHash(block)
}

func Export_generateCache(dest []uint32, epoch uint64, seed []byte) {
    generateCache(dest, epoch, seed)
}

func Export_progpowLight(size uint64, cache []uint32, hash []byte,
            nonce uint64, blockNumber uint64, cDag []uint32) ([]byte, []byte) {
    return progpowLight(size, cache, hash, nonce, blockNumber, cDag)
}

func Export_keccakF800Long(headerHash []byte, nonce uint64, result []uint32) []byte {
    return keccakF800Long(headerHash, nonce, result)
}

func Export_keccakF800Short(headerHash []byte, nonce uint64, result []uint32) uint64 {
    return keccakF800Short(headerHash, nonce, result)
}

func Export_makeHasher(h hash.Hash) Hasher {
    return makeHasher(h)
}

func Export_generateDatasetItem(cache []uint32, index uint32, keccak512 Hasher) []byte {
    return generateDatasetItem(cache, index, keccak512)
}

