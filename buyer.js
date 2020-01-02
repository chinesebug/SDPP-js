
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
const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: {
    type: 'spki',
    format: 'pem'
  },
  privateKeyEncoding: {
    type: 'pkcs8',
    format: 'pem',
    cipher: 'aes-256-cbc',
    passphrase: 'top secret'
  }
});
const encrypt_key = privateKey;
const encrypt_public_key = publicKey;
console.log('encrypt_pub: '+ encrypt_public_key)
console.log('encrypt: ' + encrypt_key)

const{ signature_key, signature_public_key } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: {
    type: 'spki',
    format: 'pem'
  },
  privateKeyEncoding: {
    type: 'pkcs8',
    format: 'pem',
    cipher: 'aes-256-cbc',
    passphrase: 'top secret'
  }
});
const signature_key = privateKey;
const signature_public_key = publicKey;
console.log('sig_pub: '+ signature_public_key)
console.log('sig: ' + signature_key)

var orderData;
var data_type;
var quantity;
var currency;
var counter =1;
var remaining;
/////////////////////////////////////////////////////////////
function sign(plaintext){
  sign.update(plaintext);
  sign.end();
  var signature = sign.sign(privateKey);
  return signature;
}

function verifysignature(planitext,sig){
  verify.update(plaintext);
  verify.end();
  return verify.verify(signature_pub_key,sig);
}
//AES, do we want iv???
function encrypt(text){
  var encrypted;
  encrypted += cipher.update(plaintext,'utf8','base64');
  encrypted += cipher.final('base64');
  return encrypted;
}

function decrypt(content){
  var decrypted;
  decrypted = decipher.update(encrypted, 'base64', 'utf8');
  decrypted += decipher.final('utf8');
}

function prepareJSONstring(message_type, data){
  var json_data = {}

  json_data['message_type'] = message_type
  json_data['data'] = data


  return JSON.stringify(json_data);
}

function prepareOrderData(data_type,quantity,currency){
  data = {}

  data['data_type'] = data_type
  data['quantity'] = quantity
  data['currency'] = currency

  //data['signature-key'] = signature_key.publickey().exportKey('OpenSSH')
  //data['encryption-key'] = encrypt_key.publickey().exportKey('OpenSSH')

  //data['address'] = invoice_address
  return prepareJSONstring("order", data)
}

function sendOrder(data_type,quantity,currency){
  json_string = prepareOrderData(data_type,quantity,currency)
  remaining = quantity;
  client.write(json_string);
  console.log('Sent Order:',json_string)
}

async function enterOrder(){
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

//function receiveData(jsonData){
  //make file
//}

function sendACK(){
  send_message_type = "DATA_ACK"
  //transaction_hash = None
  send_data = "1"
  //send_signature = None
  console.log('ACK sent #' + counter);
  json_string = prepareJSONstring(send_message_type, data);
  client.write(json_string);

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
  console.log('DATA: ' + data);
  jsonData = JSON.parse(data);

  if((jsonData.message_type == 'DATA' || jsonData.message_type == 'DATA_INVOICE') &&remaining >0){
    //receiveData(jsonData);
    sendACK();
    remaining--;
  }
// Close the client socket completely
});

enterOrder();

// Add a 'close' event handler for the client socket

client.on('close', function() {
  console.log('Connection closed');
});




/////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////
