var events = require('events');
var crypto = require('crypto');
var SHA3 = require('sha3');
var async = require('async');
var http = require('http');

var bignum = require('bignum');

var util = require('./util.js');
var blockTemplate = require('./blockTemplate.js');


//Unique extranonce per subscriber
var ExtraNonceCounter = function () {
    var counter = 0x0000501D; //0x0000GOLD
    this.next = function () {
        var extraNonce = new Buffer(8);
        extraNonce.writeUIntBE(crypto.randomBytes(4).readUIntLE(0, 4), 0, 4);
        extraNonce.writeUIntBE(counter++, 4, 4);
        if(counter >= 0xFFFFFFFF) counter = 0;
//        console.log(Math.abs(counter)); // debug
        return extraNonce.toString('hex');
    };
    this.size = 8; //bytes
};

//Unique job per new block template
var JobCounter = function () {
    var counter = 0x0000cccc;

    this.next = function () {
        counter++;
        if (counter % 0xffffffffff === 0)
            counter = 1;
        return this.cur();
    };

    this.cur = function () {
        var counter_buf = new Buffer(32);
        counter_buf.writeUIntBE('000000000000000000000000', 0, 24);
        counter_buf.writeUIntBE(counter, 24, 8);
        return counter_buf.toString('hex');
    };
};
function isHexString(s) {
    var check = String(s).toLowerCase();
    if(check.length % 2) {
        return false;
    }
    for (i = 0; i < check.length; i=i+2) {
        var c = check[i] + check[i+1];
        if (!isHex(c))
            return false;
    }
    return true;
}
function isHex(c) {
    var a = parseInt(c,16);
    var b = a.toString(16).toLowerCase();
    if(b.length % 2) {
        b = '0' + b;
    }
    if (b !== c) {
        return false;
    }
    return true;
}

/**
 * Emits:
 * - newBlock(blockTemplate) - When a new block (previously unknown to the JobManager) is added, use this event to broadcast new jobs
 * - share(shareData, blockHex) - When a worker submits a share. It will have blockHex if a block was found
 **/
var JobManager = module.exports = function JobManager(options) {

    var emitLog = function (text) {
        _this.emit('log', 'debug', text);
    };
    var emitWarningLog = function (text) {
        _this.emit('log', 'warning', text);
    };
    var emitErrorLog = function (text) {
        _this.emit('log', 'error', text);
    };
    var emitSpecialLog = function (text) {
        _this.emit('log', 'special', text);
    };

    //private members
    var _this = this;
    var jobCounter = new JobCounter();

    var shareMultiplier = algos[options.coin.algorithm].multiplier;

    //public members

    this.extraNonceCounter = new ExtraNonceCounter();

    this.currentJob;
    this.validJobs = {};

    var hashDigest = algos[options.coin.algorithm].hash(options.coin);

    var coinbaseHasher = (function () {
        switch (options.coin.algorithm) {
            default:
                return util.sha256d;
        }
    })();


    var blockHasher = (function () {
        switch (options.coin.algorithm) {
            case 'sha1':
                return function (d) {
                    return util.reverseBuffer(util.sha256d(d));
                };
            default:
                return function (d) {
                    return util.reverseBuffer(util.sha256(d));
                };
        }
    })();

    this.updateCurrentJob = function (rpcData) {
        var tmpBlockTemplate = new blockTemplate(
            jobCounter.next(),
            rpcData,
            options.coin.reward,
            options.recipients,
            options.address
        );

        _this.currentJob = tmpBlockTemplate;

        _this.emit('updatedBlock', tmpBlockTemplate, true);

        _this.validJobs[tmpBlockTemplate.jobId] = tmpBlockTemplate;

    };

    //returns true if processed a new block
    this.processTemplate = function (rpcData) {

        /* Block is new if A) its the first block we have seen so far or B) the blockhash is different and the
         block height is greater than the one we have */
        var isNewBlock = typeof(_this.currentJob) === 'undefined';
        if (!isNewBlock && _this.currentJob.rpcData.previousblockhash !== rpcData.previousblockhash) {
            isNewBlock = true;

            //If new block is outdated/out-of-sync than return
            if (rpcData.height < _this.currentJob.rpcData.height)
                return false;
        }

        if (!isNewBlock) return false;


        var tmpBlockTemplate = new blockTemplate(
            jobCounter.next(),
            rpcData,
            options.coin.reward,
            options.recipients,
            options.address
        );

        this.currentJob = tmpBlockTemplate;

        this.validJobs = {};
        _this.emit('newBlock', tmpBlockTemplate);

        this.validJobs[tmpBlockTemplate.jobId] = tmpBlockTemplate;

        return true;

    };

    this.processShare = function (miner_given_jobId, previousDifficulty, difficulty, miner_given_nonce, ipAddress, port, workerName, miner_given_header, miner_given_mixhash, callback_parent) {

        var submitTime = Date.now() / 1000 | 0;

        var shareError = function (error) {
            _this.emit('share', {
                job: miner_given_jobId,
                ip: ipAddress,
                worker: workerName,
                difficulty: difficulty,
                error: error[1]
            });
            callback_parent( {error: error, result: null});
            return;
        };

        var job = this.validJobs[miner_given_jobId];

        if (typeof job === 'undefined' || job.jobId != miner_given_jobId)
            return shareError([20, 'job not found']);

        //calculate our own header hash, do not trust miner-given value
        var headerBuffer = job.serializeHeader(); // 140 bytes, doesn't contain nonce or mixhash/solution
        let d = new SHA3.SHA3Hash(256);
        d.update(headerBuffer);
        var header_hash = util.reverseBuffer(new Buffer(d.digest('hex'), 'hex')).toString('hex');

        if (job.curTime < (submitTime - 600))
            return shareError([20, 'job is too old']);

        if (!isHexString(miner_given_header))
            return shareError([20, 'invalid header hash, must be hex']);
            
        if (header_hash != miner_given_header)
            return shareError([20, 'invalid header hash']);
        
        if (!isHexString(miner_given_nonce))
            return shareError([20, 'invalid nonce, must be hex']);
        
        if (!isHexString(miner_given_mixhash))
            return shareError([20, 'invalid mixhash, must be hex']);
       
        if (miner_given_nonce.length !== 16)
            return shareError([20, 'incorrect size of nonce, must be 8 bytes']);
       
        if (miner_given_mixhash.length !== 64)
            return shareError([20, 'incorrect size of mixhash, must be 32 bytes']);

        if (!job.registerSubmit(header_hash.toLowerCase(), miner_given_nonce.toLowerCase()))
            return shareError([22, 'duplicate share']);


/*
        console.log("miner_sent_jobid       = "+miner_given_jobId);
        console.log("miner_sent_header_hash = "+miner_given_header);
        console.log("miner_sent_nonce       = "+miner_given_nonce);
        console.log("miner_sent_mixhash     = "+miner_given_mixhash);
        console.log('job                    = ' + miner_given_jobId);
        console.log('ip                     = ' + ipAddress);
        console.log('port                   = ' + port);
        console.log('worker                 = ' + workerName);
        console.log('height                 = ' + job.rpcData.height);
*/

        var powLimit = algos.equihash.diff; // TODO: Get algos object from argument
        var adjPow = powLimit / difficulty;
        if ((64 - adjPow.toString(16).length) === 0) {
            var zeroPad = '';
        }
        else {
            var zeroPad = '0';
            zeroPad = zeroPad.repeat((64 - (adjPow.toString(16).length)));
        }
        var target_share_hex = (zeroPad + adjPow.toString(16)).substr(0,64);
		
		/*
        console.log('job                    = ' + miner_given_jobId);
        console.log('worker                 = ' + workerName);
        console.log('difficulty             = ' + difficulty);
        console.log('target_share_hex       = ' + target_share_hex);
        */
        
        var blockHashInvalid;
        var blockHash;
        var blockHex;
        
        //ProgPoW light validation
        /*
        GET /light_verify_progpow
            ?header_hash=HEADER_HASH
            &nonce=NONCE
            &mix_hash=MIX_HASH
            &share_boundary=SHARE_BOUNDARY
            &block_boundary=BLOCK_BOUNDARY
            &epoch_number=EPOCH_NUMBER
        */
        async.series([
            function(callback) {
                http.get('http://'+global.progpow_wrapper_server+'/light_verify_progpow?header_hash='+header_hash
                                                    +'&nonce='+bignum(miner_given_nonce, 16)
                                                    +'&mix_hash='+miner_given_mixhash
                                                    +'&share_boundary='+target_share_hex
                                                    +'&block_boundary='+job.target_hex
                                                    +'&epoch_number='+job.epoch_number
                                                    
                , function (res) {
                    res.setEncoding("utf8");
                    let body = "";
                    res.on("data", data => {
                        body += data;
                    });
                    res.on("end", () => {
                        body = JSON.parse(body);
                        if (body.result==true) {
                            /*
                            console.log('Progpow verify OK!\n    header_hash='+header_hash
                                    +'  \n    nonce='+bignum(miner_given_nonce, 16)
                                    +'  \n    mix_hash='+miner_given_mixhash
                                    +'  \n    share_boundary='+target_share_hex
                                    +'  \n    block_boundary='+job.target_hex
                                    +'  \n    epoch_number='+job.epoch_number
                                    +'  \n    Result= '+body.result
                                    +"  \n    Digest= "+body.digest
                                    +"  \n    MixHash= "+body.mixhash
                                    +"  \n    Info= "+body.info
                                    +"  \n    Block= "+body.block);
                            emitLog('Progpow verify OK!');
                            */
                            
                    
                            if (body.block) {
                                //good share to be a block
                                blockHex = job.serializeBlock(new Buffer(header_hash, 'hex'), new Buffer(miner_given_nonce, 'hex'), new Buffer(body.mixhash, 'hex')).toString('hex');
                                blockHash = body.digest;
                            }
                            callback(null, true);
                            return;
                        } else if (body.result==false) {
                            /*
                            console.log('Progpow verify failed!\n    header_hash='+header_hash
                                    +'  \n    nonce='+bignum(miner_given_nonce, 16)
                                    +'  \n    mix_hash='+miner_given_mixhash
                                    +'  \n    share_boundary='+target_share_hex
                                    +'  \n    block_boundary='+job.target_hex
                                    +'  \n    epoch_number='+job.epoch_number
                                    +'  \n    Result= '+body.result
                                    +"  \n    Digest= "+body.digest
                                    +"  \n    MixHash= "+body.mixhash
                                    +"  \n    Info= "+body.info
                                    +"  \n    Block= "+body.block);
                            */
                            emitWarningLog('Progpow verify FAILED!');
                            
                            
                            callback('progpow verify returned false, share discarded', false);
                            return shareError([20, 'bad share: '+body.info]);
                        } else {
                            callback('error: GET http://'+global.progpow_wrapper_server+'/light_verify_progpow?header_hash='+header_hash
                                                    +'&nonce='+bignum(miner_given_nonce, 16)
                                                    +'&mix_hash='+miner_given_mixhash
                                                    +'&share_boundary='+target_share_hex
                                                    +'&block_boundary='+job.target_hex
                                                    +'&epoch_number='+job.epoch_number+' failed, returned: body='+body + "   body.result="+body.result, false);
                            return shareError([20, 'bad share']);
                        }
                    });
                });
            },
            function(callback) {

                var blockDiffAdjusted = job.difficulty * shareMultiplier
                var shareDiffFixed = undefined;
                
                if (blockHash !== undefined) {
                    var headerBigNum = bignum.fromBuffer(blockHash, {endian: 'little', size: 32});
                    var shareDiff = diff1 / headerBigNum.toNumber() * shareMultiplier;
                    shareDiffFixed = shareDiff.toFixed(8);
                }

                /*
                console.log('blockReward: ' + job.rpcData.reward);
                console.log('difficulty: ' + difficulty);
                console.log('shareDiff: ' + shareDiff.toFixed(8));
                console.log('blockDiff: ' + blockDiffAdjusted);
                console.log('blockDiffActual: ' + job.difficulty);
                console.log('blockDiffAdjusted: ' + blockDiffAdjusted);
                console.log('blockHash: ' + blockHash);
                console.log('blockHex: ' + blockHex);
                console.log('blockHashInvalid: ' + blockHashInvalid);
                */

                _this.emit('share', {
                    job: miner_given_jobId,
                    ip: ipAddress,
                    port: port,
                    worker: workerName,
                    height: job.rpcData.height,
                    blockReward: job.rpcData.coinbasevalue,
                    difficulty: difficulty,
                    shareDiff: shareDiffFixed,
                    blockDiff: blockDiffAdjusted,
                    blockDiffActual: job.difficulty,
                    blockHash: blockHash,
                    blockHashInvalid: blockHashInvalid
                }, blockHex);
                
                callback_parent({result: true, error: null, blockHash: blockHash});
                callback(null, true);
                return;
            }
        ], function(err, results) {
            if (err != null) {
                emitErrorLog("ProgPoW verify failed, ERRORS: "+err);
                return;
            }
        });
    };
};
JobManager.prototype.__proto__ = events.EventEmitter.prototype;
