var bignum = require('bignum');
var crypto = require('crypto');
var SHA3 = require('sha3');

var merkle = require('./merkleTree.js');
var transactions = require('./transactions.js');
var util = require('./util.js');

    
/**
 * The BlockTemplate class holds a single job.
 * and provides several methods to validate and submit it to the daemon coin
**/
var BlockTemplate = module.exports = function BlockTemplate(jobId, rpcData, reward, recipients, poolAddress){

    //epoch length
    const EPOCH_LENGTH = 2800;
    
    //private members
    var submits = [];

    //public members
    this.rpcData = rpcData;
    this.jobId = jobId;

    // get target info
    this.target = bignum(rpcData.target, 16);
    this.target_hex = rpcData.target;

    this.difficulty = parseFloat((diff1 / this.target.toNumber()).toFixed(9));

    //nTime
    var nTime = util.packUInt32LE(rpcData.curtime).toString('hex');

    //current time of issuing the template
    var curTime = Date.now() / 1000 | 0;

    // generate the fees and coinbase tx
    var blockReward = this.rpcData.coinbasevalue;
    var charityReward = this.rpcData.charityvalue;
 
    var fees = [];
    rpcData.transactions.forEach(function(value) {
        fees.push(value);
    });
    this.rewardFees = transactions.getFees(fees);
    rpcData.rewardFees = this.rewardFees;

    if (typeof this.genTx === 'undefined') {
        this.genTx = transactions.createGeneration(rpcData, blockReward, charityReward, this.rewardFees, recipients, poolAddress).toString('hex');
        this.genTxHash = transactions.txHash();
        
        /*
        console.log('this.genTxHash: ' + transactions.txHash());
        console.log('this.merkleRoot: ' + merkle.getRoot(rpcData, this.genTxHash));
        */
    }

    // generate the merkle root
    this.prevHashReversed = util.reverseBuffer(new Buffer(rpcData.previousblockhash, 'hex')).toString('hex');
    this.merkleRoot = merkle.getRoot(rpcData, this.genTxHash);
    this.txCount = this.rpcData.transactions.length + 1; // add total txs and new coinbase
    this.merkleRootReversed = util.reverseBuffer(new Buffer(this.merkleRoot, 'hex')).toString('hex');
    // we can't do anything else until we have a submission


    this.serializeHeader = function() {
        var header =  new Buffer(140); //only first 108 bytes are used, rest are zeroed
        var position = 0;

        /*
        console.log('nonce:' + nonce);
        console.log('this.rpcData.bits: ' + this.rpcData.bits);
        console.log('nTime: ' + nTime);
        console.log('this.merkleRootReversed: ' + this.merkleRoot);
        console.log('this.prevHashReversed: ' + this.prevHashReversed);
        console.log('this.rpcData.version: ' + this.rpcData.version);
        console.log("bits in GBT = " + this.rpcData.bits);
        */

        header.writeUInt32LE(this.rpcData.version, position += 0, 4, 'hex');
        header.write(this.prevHashReversed, position += 4, 32, 'hex');
        header.write(this.merkleRootReversed, position += 32, 32, 'hex');
        header.write(util.packUInt32LE(this.rpcData.height).toString('hex'), position += 32, 4, 'hex');  //hashReserved
        header.write('00000000000000000000000000000000000000000000000000000000', position += 4, 28, 'hex');
        header.write(nTime, position += 28, 4, 'hex');
        header.write(util.reverseBuffer(new Buffer(rpcData.bits, 'hex')).toString('hex'), position += 4, 4, 'hex');
        header.write('000000000000000000000000000000000000000000000000000000000000', position += 4, 32, 'hex');
        return header;
    };
    
    this.serializeHeader_submit = function() {
        var header =  new Buffer(108);
        var position = 0;

        header.writeUInt32LE(this.rpcData.version, position += 0, 4, 'hex');
        header.write(this.prevHashReversed, position += 4, 32, 'hex');
        header.write(this.merkleRootReversed, position += 32, 32, 'hex');
        header.write(util.packUInt32LE(this.rpcData.height).toString('hex'), position += 32, 4, 'hex');  //hashReserved
        header.write('00000000000000000000000000000000000000000000000000000000', position += 4, 28, 'hex');
        header.write(nTime, position += 28, 4, 'hex');
        header.write(util.reverseBuffer(new Buffer(rpcData.bits, 'hex')).toString('hex'), position += 4, 4, 'hex'); //<< change bits endianness in bits coding
        return header;
    };

    // join the header and txs together
    this.serializeBlock = function (header_hash, nonce, mixhash) { //function(header, soln){

        var varInt = util.varIntBuffer(this.txCount);
        var varInt_mixhash = util.varIntBuffer(32);
        
        var nonce2 =  new Buffer(32);
        nonce2.write(util.reverseBuffer(nonce).toString('hex'), 24, 32, 'hex');

        var mixhash2 =  new Buffer(32);
        mixhash2.write(util.reverseBuffer(mixhash).toString('hex'), 0, 32, 'hex');
        
		/*
        console.log('serializeBlock header_hash=' + header_hash.toString('hex'));
        console.log('serializeBlock this.serializeHeader()=' +  this.serializeHeader().toString('hex').substr(0,216));
        console.log('serializeBlock this.serializeHeader_submit()=' +  this.serializeHeader_submit().toString('hex'));
        console.log('serializeBlock nonce=' + nonce.toString('hex'));
        console.log('serializeBlock nonce2=' + nonce2.toString('hex'));
        console.log('serializeBlock mixhash=' + mixhash.toString('hex'));
        console.log('serializeBlock mixhash2=' + mixhash2.toString('hex'));
        console.log('serializeBlock varInt=' + varInt.toString('hex'));
        console.log('serializeBlock varInt_mixhash=' + varInt_mixhash.toString('hex'));
        console.log('serializeBlock genTx=' + new Buffer(this.genTx, 'hex').toString('hex'));
        */
        
        buf = new Buffer.concat([
            this.serializeHeader_submit(),
            nonce2,
            varInt_mixhash,
            mixhash2,
            varInt,
            new Buffer(this.genTx, 'hex')
        ]);

        if (this.rpcData.transactions.length > 0) {
            this.rpcData.transactions.forEach(function (value) {
                tmpBuf = new Buffer.concat([buf, new Buffer(value.data, 'hex')]);
                buf = tmpBuf;
            });
        }

        /*
        console.log('header: ' + header.toString('hex'));
        console.log('soln: ' + soln.toString('hex'));
        console.log('varInt: ' + varInt.toString('hex'));
        console.log('this.genTx: ' + this.genTx);
        console.log('data: ' + value.data);
        console.log('buf_block: ' + buf.toString('hex'));
        console.log('blockhex: ' + buf.toString('hex'));
        */
        return buf;
    };

    // submit header_hash and nonce
    this.registerSubmit = function(header, nonce){
        var submission = header + nonce;
        if (submits.indexOf(submission) === -1){
            submits.push(submission);
            return true;
        }
        return false;
    };


    //powLimit * difficulty
    var powLimit = algos.equihash.diff; // TODO: Get algos object from argument
    var adjPow = (powLimit / this.difficulty);
    if ((64 - adjPow.toString(16).length) === 0) {
        var zeroPad = '';
    }
    else {
        var zeroPad = '0';
        zeroPad = zeroPad.repeat((64 - (adjPow.toString(16).length)));
    }
    var target = (zeroPad + adjPow.toString(16)).substr(0,64);
    //this.target_share_hex = target;

    let d = new SHA3.SHA3Hash(256);
    var seedhash_buf = new Buffer(32);
    var seedhash = seedhash_buf.toString('hex');
    this.epoch_number = Math.floor(this.rpcData.height / EPOCH_LENGTH);
    for (var i=0; i<this.epoch_number; i++) {
        d = new SHA3.SHA3Hash(256);
        d.update(seedhash_buf);
        seedhash_buf = d.digest();
        seedhash = d.digest('hex');
        //console.log("seedhash(#"+i+")= "+seedhash.toString('hex'));
    }
    
    var header_hash = this.serializeHeader(); // 140 bytes (doesn't contain nonce or mixhash)
    d = new SHA3.SHA3Hash(256);
    d.update(header_hash);
    header_hash = util.reverseBuffer(new Buffer(d.digest('hex'), 'hex')).toString('hex');

    //override for genesis block generation:
    /*
    header_hash = 'b9ecea2aba476c7c04e4e3558b8362cc3b9305349c1d5247048eb182bbf92dff';
    target =      '000000ffff000000000000000000000000000000000000000000000000000000';
    seedhash =    '0000000000000000000000000000000000000000000000000000000000000000';
    */
	
    //change override_target to a minimum wanted target. This is useful for e.g. testing on testnet.
    var override_target = 0;
    //override_target = 0x0000000FFFFF0000000000000000000000000000000000000000000000000000;
	if ((override_target != 0) && (adjPow > override_target)) {
		zeroPad = '0';
        zeroPad = zeroPad.repeat((64 - (override_target.toString(16).length)));
        target = (zeroPad + override_target.toString(16)).substr(0,64);
    }
    
    //console.log("seedhash             = "+seedhash+"   epoch_number= "+this.epoch_number+"");
    //console.log("header_hash          = "+header_hash+"        nHeight= "+this.rpcData.height);
    //console.log("Thread " + (parseInt(process.env.forkId)+1) + ": share target         = "+target.toString('hex')+"     overridden= "+(override_target!=0));
    //console.log("Thread " + (parseInt(process.env.forkId)+1) + ": network/block target = "+(util.convertBitsToBuff((new Buffer(this.rpcData.bits, 'hex')))).toString('hex')); 

    // used for mining.notify
    this.getJobParams = function(){
        if (!this.jobParams){
            this.jobParams = [
                this.jobId,
                header_hash,
                seedhash,
                target,  //target is overridden later to match miner varDiff
                true
            ];
        }
        return this.jobParams;
    };
};

