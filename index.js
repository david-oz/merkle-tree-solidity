'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.checkProofOrderedSolidityFactory = exports.checkProofSolidityFactory = exports.merkleRoot = exports.checkProofOrdered = exports.checkProof = undefined;

var _ethereumjsUtil = require('ethereumjs-util');

// Expects elements to be Buffers of length 32
// Empty string elements will be removed prior to the buffer check
// by default, order is not preserved
function MerkleTree(elements, preserveOrder, allowDuplications) {
    if (!(this instanceof MerkleTree)) {
        return new MerkleTree(elements, preserveOrder, allowDuplications);
    }

    // remove empty strings
    this.elements = elements.filter(a => a);

    // check buffers
    if (this.elements.some(e => !(e.length == 32 && Buffer.isBuffer(e)))) {
        throw new Error('elements must be 32 byte buffers');
    }

    // if we are not preserving order, dedup and sort
    this.preserveOrder = !!preserveOrder;
    this.allowDuplications = !!allowDuplications
    if (!this.preserveOrder) {
        if(!this.allowDuplications){
            this.elements = bufDedup(this.elements);
        }
        this.elements.sort(Buffer.compare);
    }

    this.layers = getLayers(this.elements, this.preserveOrder);
}

// Two strategies for creating tree and checking proofs (preserveOrder flag)
// 1. raiden - sort the leaves of the tree, and also sort each pair of
//    pre-images, which allows you to verify the proof without the index
// 2. storj - preserve the order of the leaves and pairs of pre-images, and use
//    the index to verify the proof

// The MerkleTree is a 2d array of layers
// [ elements, combinedHashes1, combinedHashes2, ... root]
// root is a length 1 array

MerkleTree.prototype.getRoot = function () {
  return this.layers[this.layers.length - 1][0];
};

MerkleTree.prototype.getProof = function (element, hex) {
  const index = getBufIndex(element, this.elements);
  if (index == -1) {
    throw new Error('element not found in merkle tree');
  }
  return getProof(index, this.layers, hex);
};

// Expects 1-n index, converts it to 0-n index internally
MerkleTree.prototype.getProofOrdered = function (element, index, hex) {
  if (!element.equals(this.elements[index - 1])) {
    throw new Error('element does not match leaf at index in tree');
  }
  return getProof(index - 1, this.layers, hex);
};

const checkProofOrdered = function checkProofOrdered(proof, root, element, index) {
  // use the index to determine the node ordering
  // index ranges 1 to n

  let tempHash = element;

  for (let i = 0; i < proof.length; i++) {
    let remaining = proof.length - i;

    // we don't assume that the tree is padded to a power of 2
    // if the index is odd then the proof will start with a hash at a higher
    // layer, so we have to adjust the index to be the index at that layer
    while (remaining && index % 2 === 1 && index > Math.pow(2, remaining)) {
      index = Math.round(index / 2);
    }

    if (index % 2 === 0) {
      tempHash = combinedHash(proof[i], tempHash, true);
    } else {
      tempHash = combinedHash(tempHash, proof[i], true);
    }
    index = Math.round(index / 2);
  }

  return tempHash.equals(root);
};

const checkProof = function checkProof(proof, root, element) {
  return root.equals(proof.reduce((hash, pair) => {
    return combinedHash(hash, pair);
  }, element));
};

const merkleRoot = function merkleRoot(elements, preserveOrder) {
  return new MerkleTree(elements, preserveOrder).getRoot();
};

// converts buffers from MerkleRoot functions into hex strings
// merkleProof is the contract abstraction for MerkleProof.sol
const checkProofSolidityFactory = function checkProofSolidityFactory(checkProofContractMethod) {
  return function (proof, root, hash) {
    proof = '0x' + proof.map(e => e.toString('hex')).join('');
    root = bufToHex(root);
    hash = bufToHex(hash);
    return checkProofContractMethod(proof, root, hash);
  };
};

const checkProofOrderedSolidityFactory = function checkProofOrderedSolidityFactory(checkProofOrderedContractMethod) {
  return function (proof, root, hash, index) {
    proof = '0x' + proof.map(e => e.toString('hex')).join('');
    root = bufToHex(root);
    hash = bufToHex(hash);
    return checkProofOrderedContractMethod(proof, root, hash, index);
  };
};

exports.default = MerkleTree;
exports.checkProof = checkProof;
exports.checkProofOrdered = checkProofOrdered;
exports.merkleRoot = merkleRoot;
exports.checkProofSolidityFactory = checkProofSolidityFactory;
exports.checkProofOrderedSolidityFactory = checkProofOrderedSolidityFactory;


function combinedHash(first, second, preserveOrder) {
  if (!second) {
    return first;
  }
  if (!first) {
    return second;
  }
  if (preserveOrder) {
    return (0, _ethereumjsUtil.sha3)(bufJoin(first, second));
  } else {
    return (0, _ethereumjsUtil.sha3)(bufSortJoin(first, second));
  }
}

function getNextLayer(elements, preserveOrder) {
  return elements.reduce((layer, element, index, arr) => {
    if (index % 2 == 0) {
      layer.push(combinedHash(element, arr[index + 1], preserveOrder));
    }
    return layer;
  }, []);
}

function getLayers(elements, preserveOrder) {
  if (elements.length == 0) {
    return [['']];
  }
  const layers = [];
  layers.push(elements);
  while (layers[layers.length - 1].length > 1) {
    layers.push(getNextLayer(layers[layers.length - 1], preserveOrder));
  }
  return layers;
}

function getProof(index, layers, hex) {
  const proof = layers.reduce((proof, layer) => {
    let pair = getPair(index, layer);
    if (pair) {
      proof.push(pair);
    }
    index = Math.floor(index / 2);
    return proof;
  }, []);
  if (hex) {
    return '0x' + proof.map(e => e.toString('hex')).join('');
  } else {
    return proof;
  }
}

function getPair(index, layer) {
  let pairIndex = index % 2 ? index - 1 : index + 1;
  if (pairIndex < layer.length) {
    return layer[pairIndex];
  } else {
    return null;
  }
}

function getBufIndex(element, array) {
  for (let i = 0; i < array.length; i++) {
    if (element.equals(array[i])) {
      return i;
    }
  }
  return -1;
}

function bufToHex(element) {
  return Buffer.isBuffer(element) ? '0x' + element.toString('hex') : element;
}

function bufJoin() {
  for (var _len = arguments.length, args = Array(_len), _key = 0; _key < _len; _key++) {
    args[_key] = arguments[_key];
  }

  return Buffer.concat([...args]);
}

function bufSortJoin() {
  for (var _len2 = arguments.length, args = Array(_len2), _key2 = 0; _key2 < _len2; _key2++) {
    args[_key2] = arguments[_key2];
  }

  return Buffer.concat([...args].sort(Buffer.compare));
}

function bufDedup(buffers) {
  return buffers.filter((buffer, i) => {
    return getBufIndex(buffer, buffers) == i;
  });
}

/*let iots = [
    "0xae1004b7ce327450a7f5a7e8656c22c711a0222d",
    "0x0784943c5cc9a59ef21117cfc29fa98dd62bb6f0",
    "0xeca2a39f24d7540ebf402ef2e8dcdc89c2a6101a",
    "0x86f1796b2ef9fc15a4810662e048922930e07edc"
]
let elements = iots.map(e => _ethereumjsUtil.sha3(e))

const merk = MerkleTree(elements, false, false)
const proof = merk.getProof(elements[0])
let str_proof = '0x'
for (let j=0 ; j<proof.length ; j++){
    let eachProof = proof[j].toString('hex')
    str_proof += eachProof
}
let y =0 ;*/
//# sourceMappingURL=data:application/json;charset=utf-8;base64,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TyxRQUFRLE1BQVIsQ0FBZSxDQUFDLE1BQUQsRUFBUyxDQUFULEtBQWU7QUFDbkMsV0FBTyxZQUFZLE1BQVosRUFBb0IsT0FBcEIsS0FBZ0MsQ0FBdkM7QUFDRCxHQUZNLENBQVA7QUFHRCIsImZpbGUiOiJpbmRleC5qcyIsInNvdXJjZXNDb250ZW50IjpbIi8vIGh0dHBzOi8vZ2l0aHViLmNvbS9yYWlkZW4tbmV0d29yay9yYWlkZW4vYmxvYi9tYXN0ZXIvcmFpZGVuL210cmVlLnB5XG4vLyBDcmVhdGUgYSBtZXJrbGUgcm9vdCBmcm9tIGEgbGlzdCBvZiBlbGVtZW50c1xuLy8gRWxlbWVudHMgYXJlIGFzc3VtZWQgdG8gYmUgMzIgYnl0ZXMgaGFzaGVzIChCdWZmZXJzKVxuLy8gIChidXQgbWF5IGJlIGV4cHJlc3NlZCBhcyAweCBwcmVmaXhlZCBoZXggc3RyaW5ncyBvZiBsZW5ndGggNjYpXG4vLyBUaGUgYm90dG9tIGxheWVyIG9mIHRoZSB0cmVlIChsZWFmIG5vZGVzKSBhcmUgdGhlIGVsZW1lbnRzXG4vLyBBbGwgbGF5ZXJzIGFib3ZlIGFyZSBjb21iaW5lZCBoYXNoZXMgb2YgdGhlIGVsZW1lbnQgcGFpcnNcblxuLy8gVHdvIHN0cmF0ZWdpZXMgZm9yIGNyZWF0aW5nIHRyZWUgYW5kIGNoZWNraW5nIHByb29mcyAocHJlc2VydmVPcmRlciBmbGFnKVxuLy8gMS4gcmFpZGVuIC0gc29ydCB0aGUgbGVhdmVzIG9mIHRoZSB0cmVlLCBhbmQgYWxzbyBzb3J0IGVhY2ggcGFpciBvZlxuLy8gICAgcHJlLWltYWdlcywgd2hpY2ggYWxsb3dzIHlvdSB0byB2ZXJpZnkgdGhlIHByb29mIHdpdGhvdXQgdGhlIGluZGV4XG4vLyAyLiBzdG9yaiAtIHByZXNlcnZlIHRoZSBvcmRlciBvZiB0aGUgbGVhdmVzIGFuZCBwYWlycyBvZiBwcmUtaW1hZ2VzLCBhbmQgdXNlXG4vLyAgICB0aGUgaW5kZXggdG8gdmVyaWZ5IHRoZSBwcm9vZlxuXG4vLyBUaGUgTWVya2xlVHJlZSBpcyBhIDJkIGFycmF5IG9mIGxheWVyc1xuLy8gWyBlbGVtZW50cywgY29tYmluZWRIYXNoZXMxLCBjb21iaW5lZEhhc2hlczIsIC4uLiByb290XVxuLy8gcm9vdCBpcyBhIGxlbmd0aCAxIGFycmF5XG5cbmltcG9ydCB7IHNoYTMgfSBmcm9tICdldGhlcmV1bWpzLXV0aWwnXG5cbi8vIEV4cGVjdHMgZWxlbWVudHMgdG8gYmUgQnVmZmVycyBvZiBsZW5ndGggMzJcbi8vIEVtcHR5IHN0cmluZyBlbGVtZW50cyB3aWxsIGJlIHJlbW92ZWQgcHJpb3IgdG8gdGhlIGJ1ZmZlciBjaGVja1xuLy8gYnkgZGVmYXVsdCwgb3JkZXIgaXMgbm90IHByZXNlcnZlZFxuZnVuY3Rpb24gTWVya2xlVHJlZShlbGVtZW50cywgcHJlc2VydmVPcmRlciwgaWdub3JlRHVwbGljYXRpb25zKSB7XG4gICAgaWYgKCEodGhpcyBpbnN0YW5jZW9mIE1lcmtsZVRyZWUpKSB7XG4gICAgICAgIHJldHVybiBuZXcgTWVya2xlVHJlZShlbGVtZW50cywgcHJlc2VydmVPcmRlciwgaWdub3JlRHVwbGljYXRpb25zKTtcbiAgICB9XG5cbiAgICAvLyByZW1vdmUgZW1wdHkgc3RyaW5nc1xuICAgIHRoaXMuZWxlbWVudHMgPSBlbGVtZW50cy5maWx0ZXIoYSA9PiBhKTtcblxuICAgIC8vIGNoZWNrIGJ1ZmZlcnNcbiAgICBpZiAodGhpcy5lbGVtZW50cy5zb21lKGUgPT4gIShlLmxlbmd0aCA9PSAzMiAmJiBCdWZmZXIuaXNCdWZmZXIoZSkpKSkge1xuICAgICAgICB0aHJvdyBuZXcgRXJyb3IoJ2VsZW1lbnRzIG11c3QgYmUgMzIgYnl0ZSBidWZmZXJzJyk7XG4gICAgfVxuXG4gICAgLy8gaWYgd2UgYXJlIG5vdCBwcmVzZXJ2aW5nIG9yZGVyLCBkZWR1cCBhbmQgc29ydFxuICAgIHRoaXMucHJlc2VydmVPcmRlciA9ICEhcHJlc2VydmVPcmRlcjtcbiAgICBpZiAoIXRoaXMucHJlc2VydmVPcmRlcikge1xuICAgICAgICB0aGlzLmlnbm9yZUR1cGxpY2F0aW9ucyA9ICEhIGlnbm9yZUR1cGxpY2F0aW9ucztcbiAgICAgICAgaWYoIXRoaXMuaWdub3JlRHVwbGljYXRpb25zKVxuICAgICAgICAgICAgdGhpcy5lbGVtZW50cyA9IGJ1ZkRlZHVwKHRoaXMuZWxlbWVudHMpO1xuICAgICAgICB0aGlzLmVsZW1lbnRzLnNvcnQoQnVmZmVyLmNvbXBhcmUpO1xuICAgIH1cblxuICAgIHRoaXMubGF5ZXJzID0gZ2V0TGF5ZXJzKHRoaXMuZWxlbWVudHMsIHRoaXMucHJlc2VydmVPcmRlcik7XG59XG5cbk1lcmtsZVRyZWUucHJvdG90eXBlLmdldFJvb3QgPSBmdW5jdGlvbigpIHtcbiAgcmV0dXJuIHRoaXMubGF5ZXJzW3RoaXMubGF5ZXJzLmxlbmd0aCAtIDFdWzBdXG59XG5cbk1lcmtsZVRyZWUucHJvdG90eXBlLmdldFByb29mID0gZnVuY3Rpb24oZWxlbWVudCwgaGV4KSB7XG4gIGNvbnN0IGluZGV4ID0gZ2V0QnVmSW5kZXgoZWxlbWVudCwgdGhpcy5lbGVtZW50cylcbiAgaWYgKGluZGV4ID09IC0xKSB7XG4gICAgdGhyb3cgbmV3IEVycm9yKCdlbGVtZW50IG5vdCBmb3VuZCBpbiBtZXJrbGUgdHJlZScpXG4gIH1cbiAgcmV0dXJuIGdldFByb29mKGluZGV4LCB0aGlzLmxheWVycywgaGV4KVxufVxuXG4vLyBFeHBlY3RzIDEtbiBpbmRleCwgY29udmVydHMgaXQgdG8gMC1uIGluZGV4IGludGVybmFsbHlcbk1lcmtsZVRyZWUucHJvdG90eXBlLmdldFByb29mT3JkZXJlZCA9IGZ1bmN0aW9uKGVsZW1lbnQsIGluZGV4LCBoZXgpIHtcbiAgaWYgKCEoZWxlbWVudC5lcXVhbHModGhpcy5lbGVtZW50c1tpbmRleCAtIDFdKSkpIHtcbiAgICB0aHJvdyBuZXcgRXJyb3IoJ2VsZW1lbnQgZG9lcyBub3QgbWF0Y2ggbGVhZiBhdCBpbmRleCBpbiB0cmVlJylcbiAgfVxuICByZXR1cm4gZ2V0UHJvb2YoaW5kZXggLSAxLCB0aGlzLmxheWVycywgaGV4KVxufVxuXG5jb25zdCBjaGVja1Byb29mT3JkZXJlZCA9IGZ1bmN0aW9uKHByb29mLCByb290LCBlbGVtZW50LCBpbmRleCkge1xuICAvLyB1c2UgdGhlIGluZGV4IHRvIGRldGVybWluZSB0aGUgbm9kZSBvcmRlcmluZ1xuICAvLyBpbmRleCByYW5nZXMgMSB0byBuXG5cbiAgbGV0IHRlbXBIYXNoID0gZWxlbWVudFxuXG4gIGZvciAobGV0IGkgPSAwOyBpIDwgcHJvb2YubGVuZ3RoOyBpKyspIHtcbiAgICBsZXQgcmVtYWluaW5nID0gcHJvb2YubGVuZ3RoIC0gaVxuXG4gICAgLy8gd2UgZG9uJ3QgYXNzdW1lIHRoYXQgdGhlIHRyZWUgaXMgcGFkZGVkIHRvIGEgcG93ZXIgb2YgMlxuICAgIC8vIGlmIHRoZSBpbmRleCBpcyBvZGQgdGhlbiB0aGUgcHJvb2Ygd2lsbCBzdGFydCB3aXRoIGEgaGFzaCBhdCBhIGhpZ2hlclxuICAgIC8vIGxheWVyLCBzbyB3ZSBoYXZlIHRvIGFkanVzdCB0aGUgaW5kZXggdG8gYmUgdGhlIGluZGV4IGF0IHRoYXQgbGF5ZXJcbiAgICB3aGlsZSAocmVtYWluaW5nICYmIGluZGV4ICUgMiA9PT0gMSAmJiBpbmRleCA+IE1hdGgucG93KDIsIHJlbWFpbmluZykpIHtcbiAgICAgIGluZGV4ID0gTWF0aC5yb3VuZChpbmRleCAvIDIpXG4gICAgfVxuXG4gICAgaWYgKGluZGV4ICUgMiA9PT0gMCkge1xuICAgICAgdGVtcEhhc2ggPSBjb21iaW5lZEhhc2gocHJvb2ZbaV0sIHRlbXBIYXNoLCB0cnVlKVxuICAgIH0gZWxzZSB7XG4gICAgICB0ZW1wSGFzaCA9IGNvbWJpbmVkSGFzaCh0ZW1wSGFzaCwgcHJvb2ZbaV0sIHRydWUpXG4gICAgfVxuICAgIGluZGV4ID0gTWF0aC5yb3VuZChpbmRleCAvIDIpXG4gIH1cblxuICByZXR1cm4gdGVtcEhhc2guZXF1YWxzKHJvb3QpXG59XG5cbmNvbnN0IGNoZWNrUHJvb2YgPSBmdW5jdGlvbihwcm9vZiwgcm9vdCwgZWxlbWVudCkge1xuICByZXR1cm4gcm9vdC5lcXVhbHMocHJvb2YucmVkdWNlKChoYXNoLCBwYWlyKSA9PiB7XG4gICAgcmV0dXJuIGNvbWJpbmVkSGFzaChoYXNoLCBwYWlyKVxuICB9LCBlbGVtZW50KSlcbn1cblxuY29uc3QgbWVya2xlUm9vdCA9IGZ1bmN0aW9uKGVsZW1lbnRzLCBwcmVzZXJ2ZU9yZGVyKSB7XG4gIHJldHVybiAobmV3IE1lcmtsZVRyZWUoZWxlbWVudHMsIHByZXNlcnZlT3JkZXIpKS5nZXRSb290KClcbn1cblxuLy8gY29udmVydHMgYnVmZmVycyBmcm9tIE1lcmtsZVJvb3QgZnVuY3Rpb25zIGludG8gaGV4IHN0cmluZ3Ncbi8vIG1lcmtsZVByb29mIGlzIHRoZSBjb250cmFjdCBhYnN0cmFjdGlvbiBmb3IgTWVya2xlUHJvb2Yuc29sXG5jb25zdCBjaGVja1Byb29mU29saWRpdHlGYWN0b3J5ID0gZnVuY3Rpb24oY2hlY2tQcm9vZkNvbnRyYWN0TWV0aG9kKSB7XG4gIHJldHVybiBmdW5jdGlvbihwcm9vZiwgcm9vdCwgaGFzaCkge1xuICAgIHByb29mID0gJzB4JyArIHByb29mLm1hcChlID0+IGUudG9TdHJpbmcoJ2hleCcpKS5qb2luKCcnKVxuICAgIHJvb3QgPSBidWZUb0hleChyb290KVxuICAgIGhhc2ggPSBidWZUb0hleChoYXNoKVxuICAgIHJldHVybiBjaGVja1Byb29mQ29udHJhY3RNZXRob2QocHJvb2YsIHJvb3QsIGhhc2gpXG4gIH1cbn1cblxuY29uc3QgY2hlY2tQcm9vZk9yZGVyZWRTb2xpZGl0eUZhY3RvcnkgPSBmdW5jdGlvbihjaGVja1Byb29mT3JkZXJlZENvbnRyYWN0TWV0aG9kKSB7XG4gIHJldHVybiBmdW5jdGlvbihwcm9vZiwgcm9vdCwgaGFzaCwgaW5kZXgpIHtcbiAgICBwcm9vZiA9ICcweCcgKyBwcm9vZi5tYXAoZSA9PiBlLnRvU3RyaW5nKCdoZXgnKSkuam9pbignJylcbiAgICByb290ID0gYnVmVG9IZXgocm9vdClcbiAgICBoYXNoID0gYnVmVG9IZXgoaGFzaClcbiAgICByZXR1cm4gY2hlY2tQcm9vZk9yZGVyZWRDb250cmFjdE1ldGhvZChwcm9vZiwgcm9vdCwgaGFzaCwgaW5kZXgpXG4gIH1cbn1cblxuZXhwb3J0IGRlZmF1bHQgTWVya2xlVHJlZVxuZXhwb3J0IHsgY2hlY2tQcm9vZiwgY2hlY2tQcm9vZk9yZGVyZWQsIG1lcmtsZVJvb3QsIGNoZWNrUHJvb2ZTb2xpZGl0eUZhY3RvcnksXG4gIGNoZWNrUHJvb2ZPcmRlcmVkU29saWRpdHlGYWN0b3J5XG59XG5cbmZ1bmN0aW9uIGNvbWJpbmVkSGFzaChmaXJzdCwgc2Vjb25kLCBwcmVzZXJ2ZU9yZGVyKSB7XG4gIGlmICghc2Vjb25kKSB7IHJldHVybiBmaXJzdCB9XG4gIGlmICghZmlyc3QpIHsgcmV0dXJuIHNlY29uZCB9XG4gIGlmIChwcmVzZXJ2ZU9yZGVyKSB7XG4gICAgcmV0dXJuIHNoYTMoYnVmSm9pbihmaXJzdCwgc2Vjb25kKSlcbiAgfSBlbHNlIHtcbiAgICByZXR1cm4gc2hhMyhidWZTb3J0Sm9pbihmaXJzdCwgc2Vjb25kKSlcbiAgfVxufVxuXG5mdW5jdGlvbiBnZXROZXh0TGF5ZXIoZWxlbWVudHMsIHByZXNlcnZlT3JkZXIpIHtcbiAgcmV0dXJuIGVsZW1lbnRzLnJlZHVjZSgobGF5ZXIsIGVsZW1lbnQsIGluZGV4LCBhcnIpID0+IHtcbiAgICBpZiAoaW5kZXggJSAyID09IDApIHsgbGF5ZXIucHVzaChjb21iaW5lZEhhc2goZWxlbWVudCwgYXJyW2luZGV4ICsgMV0sIHByZXNlcnZlT3JkZXIpKSB9XG4gICAgcmV0dXJuIGxheWVyXG4gIH0sIFtdKVxufVxuXG5mdW5jdGlvbiBnZXRMYXllcnMoZWxlbWVudHMsIHByZXNlcnZlT3JkZXIpIHtcbiAgaWYgKGVsZW1lbnRzLmxlbmd0aCA9PSAwKSB7XG4gICAgcmV0dXJuIFtbJyddXVxuICB9XG4gIGNvbnN0IGxheWVycyA9IFtdXG4gIGxheWVycy5wdXNoKGVsZW1lbnRzKVxuICB3aGlsZSAobGF5ZXJzW2xheWVycy5sZW5ndGggLSAxXS5sZW5ndGggPiAxKSB7XG4gICAgbGF5ZXJzLnB1c2goZ2V0TmV4dExheWVyKGxheWVyc1tsYXllcnMubGVuZ3RoIC0gMV0sIHByZXNlcnZlT3JkZXIpKVxuICB9XG4gIHJldHVybiBsYXllcnNcbn1cblxuZnVuY3Rpb24gZ2V0UHJvb2YoaW5kZXgsIGxheWVycywgaGV4KSB7XG4gIGNvbnN0IHByb29mID0gbGF5ZXJzLnJlZHVjZSgocHJvb2YsIGxheWVyKSA9PiB7XG4gICAgbGV0IHBhaXIgPSBnZXRQYWlyKGluZGV4LCBsYXllcilcbiAgICBpZiAocGFpcikgeyBwcm9vZi5wdXNoKHBhaXIpIH1cbiAgICBpbmRleCA9IE1hdGguZmxvb3IoaW5kZXggLyAyKVxuICAgIHJldHVybiBwcm9vZlxuICB9LCBbXSlcbiAgaWYgKGhleCkge1xuICAgIHJldHVybiAnMHgnICsgcHJvb2YubWFwKGUgPT4gZS50b1N0cmluZygnaGV4JykpLmpvaW4oJycpXG4gIH0gZWxzZSB7XG4gICAgcmV0dXJuIHByb29mXG4gIH1cbn1cblxuZnVuY3Rpb24gZ2V0UGFpcihpbmRleCwgbGF5ZXIpIHtcbiAgbGV0IHBhaXJJbmRleCA9IGluZGV4ICUgMiA/IGluZGV4IC0gMSA6IGluZGV4ICsgMVxuICBpZiAocGFpckluZGV4IDwgbGF5ZXIubGVuZ3RoKSB7XG4gICAgcmV0dXJuIGxheWVyW3BhaXJJbmRleF1cbiAgfSBlbHNlIHtcbiAgICByZXR1cm4gbnVsbFxuICB9XG59XG5cbmZ1bmN0aW9uIGdldEJ1ZkluZGV4KGVsZW1lbnQsIGFycmF5KSB7XG4gIGZvciAobGV0IGkgPSAwOyBpIDwgYXJyYXkubGVuZ3RoOyBpKyspIHtcbiAgICBpZiAoZWxlbWVudC5lcXVhbHMoYXJyYXlbaV0pKSB7IHJldHVybiBpIH1cbiAgfVxuICByZXR1cm4gLTFcbn1cblxuZnVuY3Rpb24gYnVmVG9IZXgoZWxlbWVudCkge1xuICByZXR1cm4gQnVmZmVyLmlzQnVmZmVyKGVsZW1lbnQpID8gJzB4JyArIGVsZW1lbnQudG9TdHJpbmcoJ2hleCcpIDogZWxlbWVudFxufVxuXG5mdW5jdGlvbiBidWZKb2luKC4uLmFyZ3MpIHtcbiAgcmV0dXJuIEJ1ZmZlci5jb25jYXQoWy4uLmFyZ3NdKVxufVxuXG5mdW5jdGlvbiBidWZTb3J0Sm9pbiguLi5hcmdzKSB7XG4gIHJldHVybiBCdWZmZXIuY29uY2F0KFsuLi5hcmdzXS5zb3J0KEJ1ZmZlci5jb21wYXJlKSlcbn1cblxuZnVuY3Rpb24gYnVmRGVkdXAoYnVmZmVycykge1xuICByZXR1cm4gYnVmZmVycy5maWx0ZXIoKGJ1ZmZlciwgaSkgPT4ge1xuICAgIHJldHVybiBnZXRCdWZJbmRleChidWZmZXIsIGJ1ZmZlcnMpID09IGlcbiAgfSlcbn1cbiJdfQ==