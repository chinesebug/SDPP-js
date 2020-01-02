
var net = require('net');
const iota = require('./iotaModule');
//var JsonSocket = require('json-socket');
const fs = require('fs');


var port = 8081;
var host = '127.0.0.1';

const sender_seed = 'RAHULRAHULRAHULRAHULRAHULRAHULRAHULRAHULRAHULRAHULRAHULRAHULRAHULRAHULRAHUL9RAHUL';
const recv_address ='HELLOWORLDHELLOWORLDHELLOWORLDHELLOWORLDHELLOWORLDHELLOWORLDHELLOWORLDHELLOWORLDD';

/////for sign, hash, encryption///////
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
    //cipher: 'aes-256-cbc',
    //passphrase: 'top secret'
  }
});

const key = privateKey;
const seller_public_key = publicKey
//console.log('pub: '+ publicKey)
//console.log('private: ' + privateKey)

var hash = crypto.createHash('sha256')
var randomBytes = crypto.randomBytes(16);
hash.update(randomBytes);
const secret_key = hash.digest();//

/////////set value////////
const payment_address = sender_seed;
const signature_required = 1
const payment_granularity = 5
const bs = 32
const verification = 0;
////////from buyer////////
var signature_public_key = '';
var invoice_address = ''
var encrypt_public_key = ''
var data_type = ''
var quantity = 0
var currency = 'iota'

///////variable///////
var menu = {}
var orderData
var lines
var dataLine
var counter = 1;
var remaining;

/////////////////////////////////////////////////////////////
//////////////////// helper function ////////////////////////
function signData(plaintext, signKey){
  var sign = crypto.createSign('RSA-SHA256');
  sign.update(plaintext);
  sign.end();
  var signature = sign.sign(signKey,'hex');
  return signature;
}

function verifysignature(sig,signature_pub_key){
  var verify = crypto.createVerify('RSA-SHA256');
  verify.update(sig);
  verify.end();
  return verify.verify(signature_pub_key,sig,'hex');
}
//AES, do we want iv???
function encrypt(text,encrypt_key){
  var cipher = crypto.createCipher('aes-256-cbc',encrypt_key)
  var encrypted = {};
  encrypted += cipher.update(text,'utf8','base64');
  encrypted += cipher.final('base64');
  console.log(typeof encrypted)
  return encrypted;
}

function decrypt(content,decrypt_key){
  var decipher = crypto.createDecipher('aes-256-cbc',decrypt_key)
  var decrypted = {};
  decrypted += decipher.update(encrypted, 'base64', 'utf8');
  decrypted += decipher.final('utf8');
}

function prepareJSONstring(message_type, data,signature,verification){
  var json_data = {}

  json_data.message_type = message_type
  json_data.data = data

  if (signature_required ==1){
        json_data.signature = signature;
      } else{
        json_data.signature = '';
      }
  if (verification ==1){
        json_data.verification = verification
    } else{
        json_data.verification = '';
    }
  return JSON.stringify(json_data);
}

function prepareMenuData(){

  rawdata = fs.readFileSync('menu.json');
  menu = JSON.parse(rawdata);

  menu.payment_address = payment_address
  menu.payment_granularity = payment_granularity.toString()
  menu.signature_required = signature_required.toString()
  menu.seller_public_key = seller_public_key

  console.log('existing menu: %s', JSON.stringify(menu,null, 2));
  jsonData = JSON.stringify(menu);
  signature = signData(jsonData,key);

  return prepareJSONstring('MENU',jsonData,signature);
}

function getData(orderData){
  data_type = orderData.data.data_type;
  quantity = orderData.data.quantity;
  currency = orderData.data.currency;
  cost = menu.data_type;

  signature_public_key = orderData.data.signature_public_key.toString();
  encrypt_public_key = orderData.data.encrypt_public_key.toString();
  var order_signature = orderData.signature.toString();
  console.log('Sig: ',order_signature)
  console.log('key: ', signature_public_key)
  if(signature_required == 1){
    var check = verifysignature(order_signature,signature_public_key);
    console.log('check: ' + check)
    if(!check){
      console.log('!!!Wrong Sig!!! ');
      //server.close()
    }
  }
  remaining = quantity;
  counter = 1;

  filepath = 'actual_data/'+data_type+'.txt';
  var rawdata = fs.readFileSync(filepath);
  lines = rawdata.toString().split('\n');
  console.log(lines);
  console.log('----------Start Data Transfer-----------');
  return lines;
}

/////////////////////////////////////////////////////////////
///////////////////////Main Protocol/////////////////////////
var server = net.createServer();
server.listen(port, host,function() {
  console.log('server listening to %j', server.address());
});
server.on('connection', handleConnection);

function handleConnection(conn) {
  var remoteAddress = conn.remoteAddress + ': ' + conn.remotePort;
  console.log('new client connection from %s', remoteAddress);
  sendMenu();
  //receiveOrder();
  conn.on('data',handleData);

  function sendMenu(){
    menuData = prepareMenuData();
    //json_string = JSON.stringify(menu,null,2);
    conn.write(menuData);
    console.log('Menu Sent');
  }

  function handleData(data){
    jsonData = JSON.parse(data);
    console.log('Received Data! Data Type: ',jsonData.message_type,' \n')

    if (jsonData.message_type == 'DATA_ACK'){
      dataTransfer(dataLine);
    }
    if (jsonData.message_type == 'order'){
      receiveOrder(data);
    }
  }

  function receiveOrder(data){
    //global invoice_address, encrypt_pub_key, signature_pub_key, data_type, quantity, currency
    orderData = JSON.parse(data);
    insideData = orderData.data;
    console.log('Order Information: \n',JSON.stringify(insideData,null,2));
    dataLine = getData(orderData);
    sendSessionKey();
    dataTransfer(dataLine);
  }

  function sendSessionKey(){

    var key_info = prepareJSONstring('session_key', secret_key,encrypt_public_key,0,0);
    //key_info = encrypt(key_info,encrypt_public_key);
    console.log('Session Key sent:  \n', key_info)
    conn.write(key_info);
  }
  function dataTransfer(dataLine){
    if(counter <= quantity){
      data = {}
      data.data = lines[counter-1]
      data =JSON.stringify(data);
      //data = encrypt(data, secret_key);
      signature = signData(data,key);
      //transaction_hash = None
      message_type = "DATA"

      if (counter % payment_granularity == 0){
          remaining = remaining - payment_granularity
          data_invoice = "Sent: " + payment_granularity
          data_invoice += "\nCost: " + payment_granularity*cost
          console.log('Invoice recorded: ');
          sending_message = 'SDPP_DATA_INVOICE';
          transaction_hash = iota.sendTranscation(sender_seed, recv_address, sending_message);
          data['invoice'] = (payment_granularity*cost).toString();
          message_type = "DATA_INVOICE"
      }

        json_string = prepareJSONstring(message_type, data,signature,'')
        console.log('Data Sent: \n', json_string);
        conn.write(json_string);
        counter++;
      }else{
        console.log('Sent all data!');
        conn.destroy();
      }

  }

}
