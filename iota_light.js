
// Require the IOTA libraries
const Iota = require('@iota/core');
const Converter = require('@iota/converter');
// Create a new instance of the IOTA object
// Use the `provider` field to specify which IRI node to connect to
const iota = Iota.composeAPI({
    //provider: 'http://node01.iotatoken.nl:14265'
    provider: 'https://nodes.devnet.iota.org:443'
});

module.exports =sendTokens: function (sender_seed, recv_address, amount, sending_message){
  const seed = sender_seed;
  const address = recv_address;
  const message = Converter.asciiToTrytes(sending_message);

  // Construct a TX to our new address
  const transfers = [
      {
          value: amount,
          address: address,
          message: message,
          tag: "SDPP"
      }
  ];

  return iota.prepareTransfers(seed, transfers)
      .then(trytes => {
          return iota.sendTrytes(trytes, 3/*depth*/, 14/*minimum weight magnitude*/)
          //min mwm is 9 for devnet, 14 for mainnet
      })
      .then(bundle => {
          //console.log(`Bundle: ${JSON.stringify(bundle, null, 1)}`)
          //console.log('.then:', bundle[0].hash)
          return bundle[0].hash;
      })
      .catch(err => {
          // Catch any errors
          console.log(err);
      });
},
