
// Require the IOTA libraries
const Iota = require('@iota/core');
const Converter = require('@iota/converter');
// Create a new instance of the IOTA object
// Use the `provider` field to specify which IRI node to connect to
const iota = Iota.composeAPI({
    //provider: 'http://node01.iotatoken.nl:14265'
    provider: 'https://nodes.devnet.iota.org:443'
});

module.exports = {

  /**
  * send a transaction
  * @param  {String} sender_seed address sending the transaction
  * @param  {String} recv_address address to receive the transaction
  * @param  {String} sending_message the message in the transaction
  */
  sendTranscation: function (sender_seed, recv_address, sending_message){
    const seed = sender_seed;
    const address = recv_address;
    const message = Converter.asciiToTrytes(sending_message);

    // Construct a TX to our new address
    const transfers = [
        {
            value: 0,
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
            return bundle[0].hash;
        })
        .catch(err => {
            // Catch any errors
            console.log(err);
        });
    },

  /**
  * find an transcation
  * @param  {String} addressToFetch the address the transcations belong to
  */
  fetchTransaction: function (addressToFetch){
    const address = addressToFetch;

    iota
        .findTransactionObjects({ addresses: [address] })
        .then(response => {
            console.log(response)
        })
        .catch(err => {
            console.error(err)
        })
  },

  /**
  * send tokens
  * @param  {String} sender_seed address sending the transaction
  * @param  {String} recv_address address to receive the transaction
  * @param  {Number} amount the amount of tokens to be sent
  */
  sendTokens: function (sender_seed, recv_address, amount, sending_message){
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

  /**
  * check the balance of the chosen address
  * @param  {String} check_address address to be checked
  */
  checkBalance: function (check_address){
    const address = check_address;

    iota
        .getBalances([address], 100)
        .then(({ balances }) => {
            console.log(balances)
        })
        .catch(err => {
            console.error(err)
        })
  },

};
