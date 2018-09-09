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

=== ProgPoW Ethash JSON wrapper ===

Wrapper calculates ProgPoW digest and mixhash for given header hash and nonce.
To do this, https://github.com/ifdefelse/go-ethereum ProgPoW implementation is used.
Input is given by issuing a GET request on http://HTTP_HOST. By default, host is
localhost and port is 8077. You can change this in progpow_ethash_wrapper.go const.

You need Go to run the software or you can use compiled x86-64 Linux binary.

Use <SKIP_MIXHASH_CHECK> = true, if you want to skip pre-progpow check validation
of miner-given mixhash (mix result hash). Default setting is 'false', which means
that mixhash is checked before light progpow verify is done. By checking the mixhash
prior to more resource consuming light progpow verify, bad results can be discarded
early.

ProgPoW fork of ZNOMP stratum-pool runs one wrapper server per thread automatically.
This uses the compiled binary.

To use Go to run ProgPoW Ethash JSON wrapper, issue the following command:
$ go run progpow_ethash_wrapper.go <HOSTNAME>:<PORT> <SKIP_MIXHASH_CHECK>
or use the standalone compiled binary:
$ ./progpow_ethash_wrapper <HOSTNAME>:<PORT> <SKIP_MIXHASH_CHECK>

If building or using Go to run, this software requires standard Go packages and
go-ethereum packages, as a fork of go-ethereum ethash is used.

Instructions for installing required Go and other packages can be found from:
https://github.com/ethereum/go-ethereum/wiki/Building-Ethereum

To build a standalone version, issue the following command:
$ go build -ldflags "-s -w" -o progpow_ethash_wrapper progpow_ethash_wrapper.go

Usage:

GET /new_epoch?epoch_number=EPOCH_NUMBER

    Do /new_epoch request whenever you want to update generated cache.
    Cache is automatically updated by /light_verify_progpow, too, when 
    epoch_number is changed from the one before.
    EPOCH_NUMBER must be the epoch number in decimal format.
    Generating a new cache based on epoch number takes few hundred
    milliseconds which is a lot less than light-verifying ProgPow.
    This is why we want to do it only when epoch changes.

    Returns {"result":true, ...} if cache was generated succesfully or
    was already generated. Otherwise returns {"result":false, ...} or if
    a fatal error occurred, returns a non-JSON error message.

GET /light_verify_progpow
    ?header_hash=HEADER_HASH
    &nonce=NONCE
    &mix_hash=MIX_HASH
    &share_boundary=SHARE_BOUNDARY
    &block_boundary=BLOCK_BOUNDARY
    &epoch_number=EPOCH_NUMBER

    Verifies header hash + mixhash + nonce. First it checks if mix result
    hash yields to correct mix result digest hash:
    (mix result digest hash <= share boundary)
    If this is true, light progpow verify is ran. Otherwise returns false.
    If light progpow verify fails, returns false. If succeeds, block
    boundary check is done. If (result hash <= block boundary) is true,
    result bool Block is true, otherwise false.
    
    Return values are in the JsonResult struct (see the end of this document).

    Header hash must be 32 bytes long, hex-encoded, and
    nonce must be given as a (uint64) decimal value.
    Mix hash is 32 byte hex-encoded value.
    Share and block boundaries are hex-encoded 32 bytes little-endian
    values. Epoch number is the decimal epoch number. If cache isn't
    generated already for the epoch number, last cache will be overridden
    by a cache for this epoch number.
    
    Example:
    GET /light_verify_progpow?header_hash=6b132042016
        69dbee3fce095299a424e809926772586424b8eb69a0c532d74a4&nonce=71
        98330389369308680&mix_hash=b54f0315ee236247346a846cfc0d43d1f04
        2e49c3eef93f505515686bb7adc6b&share_boundary=0000FFFF000000000
        00000000000000000000000000000000000000000000000&block_boundary
        =000000FFFF000000000000000000000000000000000000000000000000000
        000&epoch_number=0
    
    Returns:
    {"result":true,"digest":"000002753b3b61632c0b16af2fab4b4bf9e71ba3d
    710fbab9e870f3ee3b3a770","mixhash":"b54f0315ee236247346a846cfc0d43
    d1f042e49c3eef93f505515686bb7adc6b","info":"","block":false}


All the return values are returned in the following structure:
type JsonResult struct {
    Result bool `json:"result"`
    Digest string `json:"digest"`
    MixHash string `json:"mixhash"`
    Info string `json:"info"`
    Block bool `json:"block"`
}
