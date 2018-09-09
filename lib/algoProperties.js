var ev = require('equihashverify');
var util = require('./util.js');

var diff1 = global.diff1 = 0x00000fffff000000000000000000000000000000000000000000000000000000;
global.progpow_wrapper_server = 'localhost:'+(8701+parseInt(process.env.forkId));


var algos = module.exports = global.algos = {
    'equihash': {
        multiplier: 1,
        diff: parseInt('0x00000fffff000000000000000000000000000000000000000000000000000000'),
        hash: function(){
            return function(){
                return ev.verify.apply(this, arguments);
            }
        }
    }
};

for (var algo in algos){
    if (!algos[algo].multiplier)
        algos[algo].multiplier = 1;
}
