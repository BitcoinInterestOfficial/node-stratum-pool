// ProgPoW Ethash JSON wrapper v0.4 (2018-10-02)
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

package main

//ethash library is modified to have epochLength=1 in algorithm.go
import (
    "./ethash"
    "encoding/json"
    "encoding/hex"
    "encoding/binary"
    "bytes"
    "math/big"
    "net/http"
    "strconv"
    "fmt"
    "log"
    "os"
    "time"
    "github.com/ethereum/go-ethereum/crypto/sha3"
)

//consts
const HTTP_HOST_PORT_DEFAULT        string = "localhost:8700"   	//host and port for http server
const SKIP_MIXHASH_CHECK_DEFAULT    bool   = false					//true = skips user-given mixhash checking
const VERSION_STRING                string = "v0.4 (2018-10-02)"
const progpowCacheWords             uint32 = 4 * 1024               // Total size 16*1024 bytes


//globals
var epochNumber         uint64
var cacheSize           uint64
var datasetSize         uint64
var seedHash            []byte
var cache               []uint32
var keccak512           ethash.Hasher
var rawData             []byte
var cDag                []uint32

var skip_mixhash_check  bool        = SKIP_MIXHASH_CHECK_DEFAULT
var generating_cache    bool = false

//JSON response struct
type JsonResult struct {
    Result bool `json:"result"`
    Digest string `json:"digest"`
    MixHash string `json:"mixhash"`
    Info string `json:"info"`
    Block bool `json:"block"`
}

//handles GET /
func apiRoot(w http.ResponseWriter, r *http.Request) {
    if (r.Method == "GET") {
        json.NewEncoder(w).Encode("API usage: \nUse /new_epoch only when epoch changes. \nSet new epoch number, generates new cache: /new_epoch?epoch_number=EPOCH_NUMBER   \n  Light-verify ProgPoW solution: /light_verify_progpow?header_hash=HEADER_HASH&nonce=NONCE&mix_hash=MIX_HASH&share_boundary=SHARE_BOUNDARY&block_boundary=BLOCK_BOUNDARY&epoch_number=EPOCH_NUMBER")
    } else {
        w.WriteHeader(http.StatusMethodNotAllowed)
    }
}

//handles GET /new_epoch
func apiNewEpoch(w http.ResponseWriter, r *http.Request) {
    //only GET is allowed
    if (r.Method != "GET") {
        w.WriteHeader(http.StatusMethodNotAllowed)
        return;
    }
    
    //read epoch number from GET query
    var get_epoch_number uint64
    get_epoch_number, err := strconv.ParseUint(r.URL.Query().Get("epoch_number"), 10, 64)
    if err != nil {
        json.NewEncoder(w).Encode("error: can't parse epoch_number")
        return;
    }
    
    //initiate json response struct as false result
    json_result := JsonResult{Result: false}
    
    //check if we're generating a cache already
    if (generating_cache) {
        json_result.Result = false
        json_result.Info = "already generating cache"
    } else if get_epoch_number == epochNumber {
        //if it's the same we already had, skip making new cache etc. and return true immediately
        json_result.Result = true
    } else {
        //run newEpoch to generate new cache and set parameters to correct values
        res := newEpoch(get_epoch_number)
        if (res != false) {
            json_result.Result = true
        }
    }
    //write json response struct into JSON and send to HTTP client
    result, err := json.Marshal(&json_result)
    if err == nil {
        w.Write(result)
    } else {
        json.NewEncoder(w).Encode("error: can't encode JsonResult")
    }
}

//handles GET /light_verify_progpow
func apiLightVerifyProgpow(w http.ResponseWriter, r *http.Request) {
    //only GET is allowed
    if (r.Method != "GET") {
        w.WriteHeader(http.StatusMethodNotAllowed)
        return;
    }
    
    //init and read GET query values
    var get_nonce           uint64
    var get_header_hash     []byte
    var get_mix_hash        []byte
    var get_share_boundary  []byte
    var get_block_boundary  []byte
    var get_epoch_number    uint64
    
    //nonce
    get_nonce, err := strconv.ParseUint(r.URL.Query().Get("nonce"), 10, 64)
    if err != nil {
        json.NewEncoder(w).Encode("error: can't parse nonce")
        return;
    }
    //header hash
    get_header_hash, err2 := hex.DecodeString(r.URL.Query().Get("header_hash"))
    if err2 != nil {
        json.NewEncoder(w).Encode("error: can't parse header_hash")
        return;
    }
    if len(get_header_hash) != 32 {
        json.NewEncoder(w).Encode("error: header_hash must be 32 bytes length")
        return;
    }
    //mix hash
    get_mix_hash, err3 := hex.DecodeString(r.URL.Query().Get("mix_hash"))
    if err3 != nil {
        json.NewEncoder(w).Encode("error: can't parse mix_hash")
        return;
    }
    if len(get_mix_hash) != 32 {
        json.NewEncoder(w).Encode("error: mix_hash must be 32 bytes length")
        return;
    }
    //share boundary
    get_share_boundary, err4 := hex.DecodeString(r.URL.Query().Get("share_boundary"))
    if err4 != nil {
        json.NewEncoder(w).Encode("error: can't parse share_boundary")
        return;
    }
    if len(get_share_boundary) != 32 {
        json.NewEncoder(w).Encode("error: share_boundary must be 32 bytes length")
        return;
    }
    //block boundary
    get_block_boundary, err5 := hex.DecodeString(r.URL.Query().Get("block_boundary"))
    if err5 != nil {
        json.NewEncoder(w).Encode("error: can't parse block_boundary")
        return;
    }
    if len(get_block_boundary) != 32 {
        json.NewEncoder(w).Encode("error: block_boundary must be 32 bytes length")
        return;
    }
    //read epoch number from GET query
    get_epoch_number, err6 := strconv.ParseUint(r.URL.Query().Get("epoch_number"), 10, 64)
    if err6 != nil {
        json.NewEncoder(w).Encode("error: can't parse epoch_number")
        return;
    }
    
    //initiate json response struct as false result
    json_result := JsonResult{Result: false, Digest: "", MixHash: "", Info: "", Block: false}
    
    //if it's the same we already had, skip making new cache
    if (get_epoch_number != epochNumber) {
        //if cache is being generated, sleep while we're waiting for it to finish
        for generating_cache {
            time.Sleep(50 * time.Millisecond)
        }
        
        //if it's not the cache want, make new
        if (get_epoch_number != epochNumber) {
            //run newEpoch to generate new cache and set parameters to correct values
            res := newEpoch(get_epoch_number)
            if (res == false) {
                json.NewEncoder(w).Encode("error: failed run newEpoch")
                return;
            }
        }
    }
    
    //calculate result hash and compare it to boundary.
    // return at this point if this check fails
    result := make([]uint32, 8)
    get_mix_hash_uint32 := make([]uint32, 8)
    for i := uint32(0); i < 8; i++ {
        result[i] = 0
        get_mix_hash_uint32[i] = binary.LittleEndian.Uint32(get_mix_hash[4*i:])
    }

    res_seed := ethash.Export_keccakF800Short(get_header_hash, get_nonce, result)
    res_digest := ethash.Export_keccakF800Long(get_header_hash, res_seed, get_mix_hash_uint32[:])

    for i := 0; i < len(res_digest); i += 4 {
		binary.BigEndian.PutUint32(res_digest[i:], binary.LittleEndian.Uint32(res_digest[i:]))
	}

    res_digest_value := new(big.Int)
    res_digest_value.SetBytes(res_digest)
    
    get_share_boundary_value := new(big.Int)
    get_share_boundary_value.SetBytes(get_share_boundary)
    
    get_block_boundary_value := new(big.Int)
    get_block_boundary_value.SetBytes(get_block_boundary)
    
    /*
    //debug:
    fmt.Printf("res_seed                   = %v\n", res_seed)
    fmt.Printf("res_digest                 = %x\n", res_digest)
    fmt.Printf("share_boundary             = %x\n", get_share_boundary)
    fmt.Printf("get_block_boundary         = %x\n", get_block_boundary)
    fmt.Printf("res_digest_value           = %v\n", res_digest_value)
    fmt.Printf("get_share_boundary_value   = %v\n", get_share_boundary_value)
    fmt.Printf("get_block_boundary_value   = %v\n", get_block_boundary_value)
    fmt.Printf("res_digest_value.Cmp(get_share_boundary_value)= %v\n", (res_digest_value.Cmp(get_share_boundary_value)))
    fmt.Printf("res_digest_value.Cmp(get_block_boundary_value)= %v\n", (res_digest_value.Cmp(get_block_boundary_value)))
    */
    
    /*
     big.Int  x.Cmp(y) results:
        -1 if x <  y
         0 if x == y
        +1 if x >  y
    */

    //check if share boundary is met.
    if !skip_mixhash_check && ((res_digest_value.Cmp(get_share_boundary_value)) != -1) {
        //result hash is over share boundary: not accepted.
        json_result.Result = false
        json_result.Info = "result hash is over share boundary (1): not accepted";
        json_result.Digest = fmt.Sprintf("%x", res_digest)
        json_result.MixHash = fmt.Sprintf("%x", get_mix_hash)
    } else {
        //run progpow light
        digest, mixhash := ethash.Export_progpowLight(datasetSize, cache, get_header_hash, get_nonce, epochNumber, cDag)
        
        //swap uint32 endiannesses
        for i := 0; i < len(digest); i += 4 {
            binary.BigEndian.PutUint32(digest[i:], binary.LittleEndian.Uint32(digest[i:]))
        }
        res_digest_value = new(big.Int)
        res_digest_value.SetBytes(digest)
        
        if ((res_digest_value.Cmp(get_share_boundary_value)) != -1) {
            json_result.Result = false
            json_result.Info = "result hash is over share boundary (2): not accepted";
            json_result.Digest = fmt.Sprintf("%x", digest)
            json_result.MixHash = fmt.Sprintf("%x", mixhash)
        } else {
            //check if mix hash is what was given to us
            if skip_mixhash_check || (bytes.Equal(mixhash, get_mix_hash)) {
                //correct mixhash
                json_result.Result = true
                json_result.Digest = fmt.Sprintf("%x", digest)
                json_result.MixHash = fmt.Sprintf("%x", mixhash)
                
                //check if it's block-eligible share
                if (res_digest_value.Cmp(get_block_boundary_value)) != -1 {
                    json_result.Block = false
                } else {
                    json_result.Block = true
                }
            } else {
                //wrong mixhash
                json_result.Result = false
                json_result.Info = "wrong mixhash"
                json_result.Digest = fmt.Sprintf("%x", digest)
                json_result.MixHash = fmt.Sprintf("%x", mixhash)
            }
        }
    }


    //write json response struct into JSON and send to HTTP client
    final_result, err7 := json.Marshal(&json_result)
    if err7 == nil {
        w.Write(final_result)
    } else {
        json.NewEncoder(w).Encode("error: can't encode JsonResult")
    }  
}




//handles GET /block_hash
func apiBlockHash(w http.ResponseWriter, r *http.Request) {
    //only GET is allowed
    if (r.Method != "GET") {
        w.WriteHeader(http.StatusMethodNotAllowed)
        return;
    }
    
    //init and read GET query values
    var get_nonce           uint64
    var get_header_hash     []byte
    var get_mix_hash        []byte
    
    //nonce
    get_nonce, err := strconv.ParseUint(r.URL.Query().Get("nonce"), 10, 64)
    if err != nil {
        json.NewEncoder(w).Encode("error: can't parse nonce")
        return;
    }
    //header hash
    get_header_hash, err2 := hex.DecodeString(r.URL.Query().Get("header_hash"))
    if err2 != nil {
        json.NewEncoder(w).Encode("error: can't parse header_hash")
        return;
    }
    if len(get_header_hash) != 32 {
        json.NewEncoder(w).Encode("error: header_hash must be 32 bytes length")
        return;
    }
    //mix hash
    get_mix_hash, err3 := hex.DecodeString(r.URL.Query().Get("mix_hash"))
    if err3 != nil {
        json.NewEncoder(w).Encode("error: can't parse mix_hash")
        return;
    }
    if len(get_mix_hash) != 32 {
        json.NewEncoder(w).Encode("error: mix_hash must be 32 bytes length")
        return;
    }
    
    //initiate json response struct as false result
    json_result := JsonResult{Result: false, Digest: "", MixHash: "", Info: "", Block: false}
    
    //calculate result hash
    result := make([]uint32, 8)
    get_mix_hash_uint32 := make([]uint32, 8)
    for i := uint32(0); i < 8; i++ {
        result[i] = 0
        get_mix_hash_uint32[i] = binary.LittleEndian.Uint32(get_mix_hash[4*i:])
    }

    res_seed := ethash.Export_keccakF800Short(get_header_hash, get_nonce, result)
    res_digest := ethash.Export_keccakF800Long(get_header_hash, res_seed, get_mix_hash_uint32[:])

    for i := 0; i < len(res_digest); i += 4 {
		binary.BigEndian.PutUint32(res_digest[i:], binary.LittleEndian.Uint32(res_digest[i:]))
	}

    json_result.Result = true
    json_result.Digest = fmt.Sprintf("%x", res_digest)
    json_result.MixHash = fmt.Sprintf("%x", get_mix_hash_uint32)
    json_result.Info = "block hash calculated from header_hash + nonce + mix_result_hash"
    json_result.Block = true


    //write json response struct into JSON and send to HTTP client
    final_result, err7 := json.Marshal(&json_result)
    if err7 == nil {
        w.Write(final_result)
    } else {
        json.NewEncoder(w).Encode("error: can't encode JsonResult")
    }  
}



func main() {
    var http_host_port      string = HTTP_HOST_PORT_DEFAULT
    //check if we have set custom port in 1st cli arg
    if (len(os.Args) > 1) && (os.Args[1] != "") {
        http_host_port = os.Args[1]
    }
    //also check if we have "skip mixhash check" on
    if (len(os.Args) > 2) && (os.Args[2] != "") {
        if (os.Args[2] == "true") {
            skip_mixhash_check = true
        } else {
            skip_mixhash_check = false
        }
    }
    
    fmt.Printf("Starting ProgPoW Ethash JSON wrapper %s on http://%s  skip_mixhash_check=%t \n", VERSION_STRING, http_host_port, skip_mixhash_check)
        
    //generate first epoch
    if (newEpoch(0) != false) {
        //set HTTP paths
        http.HandleFunc("/", apiRoot)
		http.HandleFunc("/new_epoch", apiNewEpoch)
        http.HandleFunc("/light_verify_progpow", apiLightVerifyProgpow)
        http.HandleFunc("/block_hash", apiBlockHash)
		
        //start HTTP server
        log.Fatal(http.ListenAndServe(http_host_port, nil))
    } else {
        fmt.Println("ERROR: newEpoch(0) failed.");
    }
    
    fmt.Println("Done.")
}

//generates new cache for epoch_number
func newEpoch(epoch_number uint64) bool {
    generating_cache = true
    
    cacheSize   = ethash.Export_cacheSize(epoch_number)
    datasetSize = ethash.Export_datasetSize(epoch_number)
    seedHash    = ethash.Export_seedHash(epoch_number)
    
    cache       = make([]uint32, cacheSize/4)
    
    ethash.Export_generateCache(cache, epoch_number, seedHash)
    
    keccak512 = ethash.Export_makeHasher(sha3.NewKeccak512())
    
    cDag = make([]uint32, progpowCacheWords)
    rawData = ethash.Export_generateDatasetItem(cache, 0, keccak512)

    for i := uint32(0); i < progpowCacheWords; i += 2 {
        if i != 0 && 2 * i / 16 != 2 * (i - 1) / 16 {
            rawData = ethash.Export_generateDatasetItem(cache,  2 * i / 16, keccak512)
        }
        cDag[i + 0] = binary.LittleEndian.Uint32(rawData[((2 * i + 0) % 16) * 4:])
        cDag[i + 1] = binary.LittleEndian.Uint32(rawData[((2 * i + 1) % 16) * 4:])
    }
        
    fmt.Printf("newEpoch: Generated epoch cache. epoch_number= %v  old epochNumber= %v  cacheSize=%v  datasetSize= %v  seedHash= %x\n", epoch_number, epochNumber, cacheSize, datasetSize, seedHash)
    
    epochNumber = epoch_number
    generating_cache = false
    return true;
}


