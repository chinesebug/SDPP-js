
var net = require('net');
const iota = require('./iotaModule');
//var JsonSocket = require('json-socket');
const fs = require('fs');
var readline = require('readline');
const inquirer = require('inquirer');

var rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

var port = 8081;
var host = '127.0.0.1';

const sender_seed = 'RAHULRAHULRAHULRAHULRAHULRAHULRAHULRAHULRAHULRAHULRAHULRAHULRAHULRAHULRAHUL9RAHUL';
const recv_address ='HELLOWORLDHELLOWORLDHELLOWORLDHELLOWORLDHELLOWORLDHELLOWORLDHELLOWORLDHELLOWORLDD';

//////encryption, signing, hashing//////
const crypto = require('crypto');

const keyOptions = [{
  modulusLength: 2048,
  publicKeyEncoding: {
    type: 'spki',
    format: 'pem'
  },
  privateKeyEncoding: {
    type: 'pkcs8',
    format: 'pem',
    //cipher: 'aes-256-cbc',
    //passphrase: 'top secret 1'
  }
}, {
  modulusLength: 2048,
  publicKeyEncoding: {
    type: 'spki',
    format: 'pem'
  },
  privateKeyEncoding: {
    type: 'pkcs8',
    format: 'pem',
    //cipher: 'aes-256-cbc',
    //passphrase: 'top secret 2'
  }
}]

const [
  { publicKey: encrypt_public_key, privateKey: encrypt_key },
  { publicKey: signature_public_key, privateKey: signature_key }
] = keyOptions.map(options => crypto.generateKeyPairSync('rsa', options))

//console.log(signature_public_key);

const sign = crypto.createSign('RSA-SHA256');
var verify = crypto.createVerify('RSA-SHA256');
var cipher;
var decipher;

////////////////////////////////
//const payment_address = sender_seed;
//const signature_required = 1
//const payment_granularity = 5
const bs = 32
const verification_required = 1;

var payment_address = ''
var payment_granularity = 0
var secret_key;
var quantity = 0
var cost = 0
var data_type = ''
var signature_required = 0
var seller_public_key = ''


var orderData;
var data_type;
var quantity;
var currency;
var counter =1;
var remaining;
//////////////////////// helper functions ///////////////////////
function signData(plaintext, signKey){
  var sign = crypto.createSign('RSA-SHA256');
  sign.update(plaintext);
  sign.end();
  var signature = sign.sign(signKey,'hex');
  return signature;
}

function verifysignature(text,sig,signature_pub_key){
  var verify = crypto.createVerify('RSA-SHA256');
  verify.update(text);
  verify.end();
  return verify.verify(signature_pub_key,sig,'hex');
}
//AES, do we want iv???
// function encrypt(text,secret_key){
//   var cipher = crypto.createCipher('aes-256-cbc',secret_key)
//   var encrypted = '';
//
//   encrypted += cipher.update(text,'utf8','base64');
//   encrypted += cipher.final('base64');
//   return encrypted;
// }
//
// function decrypt(content, decrypt_key){
//   var decipher = crypto.createDecipher('aes-256-cbc',decrypt_key)
//   var decrypted = '';
//   decrypted += decipher.update(content, 'base64', 'utf8');
//   decrypted += decipher.final('utf8');
// }
function encrypt(text, myKey) {
 let iv = crypto.randomBytes(16);
 let cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(myKey), iv);
 let encrypted = cipher.update(text);

 encrypted = Buffer.concat([encrypted, cipher.final()]);

 return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(text, myKey) {
text =text.toString();
 let textParts = text.split(':');
 let iv = Buffer.from(textParts.shift(), 'hex');
 let encryptedText = Buffer.from(textParts.join(':'), 'hex');
 let decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(myKey), iv);
 let decrypted = decipher.update(encryptedText);

 decrypted = Buffer.concat([decrypted, decipher.final()]);

 return decrypted.toString();
}

function prepareJSONstring(message_type, data, signature,verification){
  var json_data = {}

  json_data.message_type = message_type;
  json_data.data = data;
  if (signature_required ==1){
        json_data.signature = signature;
      } else{
        json_data.signature = '';
      }
  if (verification_required ==1){
        json_data.verification = verification
    } else{
        json_data.verification = '';
    }

  return JSON.stringify(json_data);
}

function prepareOrderData(data_type,quantity,currency){
  data = {}

  data.data_type = data_type
  data.quantity = quantity
  data.currency = currency
  console.log('Order detail: ' + JSON.stringify(data,null,2))
  data.buyer_address = ''
  data.signature_public_key = signature_public_key;
  data.encrypt_public_key = encrypt_public_key;
  console.log('sign used:',signature_key)
  console.log('pubkey', signature_public_key)
  signature = signData(JSON.stringify(data),signature_key);

  return prepareJSONstring("order", data, signature)
}

function sendOrder(data_type,quantity,currency){

  json_string = prepareOrderData(data_type,quantity,currency)
  remaining = quantity;
  client.write(json_string);
  //console.log('with hash:',json_string)
}

async function enterOrder(){
  console.log('***** Enter Your Order*****')
  inquirer
    .prompt([
      {
        name: 'data_type',
        message: 'What data type would you like to order?',
        //default: 'Alligators, of course!',
      },
      {
        name: 'quantity',
        message: 'What quantity would you like to order?',
        //default: '#008f68',
      },
      {
        name: 'currency',
        message: 'What currency would you like to use?',
        //default: '#008f68',
      },
    ])
    .then(answers => {
      console.info('Answers:', answers);
      orderData = answers;
      data_type = answers.data_type;
      quantity = answers.quantity;
      currency = answers.currency;
      sendOrder(data_type,quantity,currency);

    });
}

function sendACK(){
  send_message_type = "DATA_ACK"
  //transaction_hash = None
  send_data = "1"
  //send_signature = None
  console.log('***ACK sent # ' + counter + '*** \n');
  json_string = prepareJSONstring(send_message_type, send_data, signData(JSON.stringify(data),signature_key));
  client.write(json_string);

  counter++;
}

async function sendPayACK(){

  send_message_type = "PAYMENT_ACK"
  //transaction_hash = None
  send_data = "payment"
  var transaction_hash = ''
  //send_signature = None
  payment_invoice = "Sent: " + payment_granularity
  payment_invoice += "\nPayment: " + payment_granularity*cost
  console.log('***ACK sent # ' + counter + ' with payment *** \n');
  try{
  transaction_hash = await iota.sendTokens(sender_seed, recv_address, 0, payment_invoice);
  console.log('payemnt hash: ',transaction_hash)
  json_string = prepareJSONstring(send_message_type, data, signData(JSON.stringify(data),signature_key), transaction_hash);
  client.write(json_string);



  }catch(e){
    console.log(e)
  }
  counter++;
}
/////////////////////////////////////////////////////////////
/////////////////////// Main Protocol ////////////////////////////
var client = new net.Socket();
client.connect(port, host);
client.on('connect',function() {
  console.log('CONNECTED TO: ' + host + ':' + port);
});

client.on('data', function(data) {
  jsonData = JSON.parse(data);

  if(jsonData.message_type == 'MENU'){
    rawData = jsonData.data;
    //console.log('DATA: ' + JSON.stringify(rawData,null,2));
    rawData = JSON.parse(rawData)

    payment_granularity = parseInt(rawData.payment_granularity)
    payment_address = rawData.payment_address
    signature_required = parseInt(rawData.signature_required)
    seller_public_key = rawData.seller_public_key;
    console.log('******** Menu ********: \n' + JSON.stringify(rawData,null,2));

    enterOrder();
  }

  if((jsonData.message_type == 'DATA' || jsonData.message_type == 'DATA_INVOICE') &&remaining >=0){
    console.log('***DATA # ',counter,' received!***\n' + JSON.stringify(jsonData,null,1))
    content = jsonData.data;
    //console.log(typeof content)
    //console.log(typeof secret_key)
    content = decrypt(content.toString(), secret_key);
    console.log('After decrypt: ', content,'\n');

    if(jsonData.message_type == 'DATA_INVOICE'){
      sendPayACK()
      .then(()=>{
          if(remaining <= 0){
            client.destroy();
          }
        }
      )

    }else{sendACK();}
    //console.log('***************')

    remaining--;



  }

  if(jsonData.message_type == 'session_key'){
    //console.log('key: ' , JSON.stringify(jsonData.data))
    secret_key = jsonData.data;
    secret_key = crypto.privateDecrypt(encrypt_key,Buffer.from(secret_key));
    console.log('Received session_key: \n'+ secret_key.toString('hex'))
  }
// Close the client socket completely
});

// Add a 'close' event handler for the client socket

client.on('close', function() {
  console.log('Connection closed');
});


/////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////
