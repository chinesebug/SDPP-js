
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
var randomBytes = crypto.randomBytes(32);
hash.update(randomBytes);
const secret_key = hash.digest();//

/////////set value////////
const payment_address = sender_seed;
const signature_required = 1
const payment_granularity = 5
const bs = 32
const verification_required = 1;
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
var final_sent = false;
/////////////////////////////////////////////////////////////
//////////////////// helper function ////////////////////////
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
/*
function encrypt(text,encrypt_key){
  var cipher = crypto.createCipheriv('aes-256-cbc',encrypt_key,iv)
  var encrypted = '';
  encrypted += cipher.update(text,'utf8','base64');
  encrypted += cipher.final('base64');
  console.log(typeof encrypted)
  return encrypted;
}

function decrypt(content,decrypt_key){
  var decipher = crypto.createDecipheriv('aes-256-cbc',decrypt_key,iv)
  var decrypted = '';
  decrypted += decipher.update(encrypted, 'base64', 'utf8');
  decrypted += decipher.final('utf8');
}
*/
function encrypt(text, myKey) {
 let iv = crypto.randomBytes(16);
 let cipher = crypto.createCipheriv('aes-256-cbc', myKey, iv);
 let encrypted = cipher.update(text);

 encrypted = Buffer.concat([encrypted, cipher.final()]);

 return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(text, myKey) {
 let textParts = text.split(':');
 let iv = Buffer.from(textParts.shift(), 'hex');
 let encryptedText = Buffer.from(textParts.join(':'), 'hex');
 let decipher = crypto.createDecipheriv('aes-256-cbc', myKey, iv);
 let decrypted = decipher.update(encryptedText);

 decrypted = Buffer.concat([decrypted, decipher.final()]);

 return decrypted.toString();
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
  if (verification_required ==1){
        json_data.verification = verification
    } else{
        json_data.verification = '';
    }
    //console.log(json_data.verification)
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
  //console.log(typeof orderData.data.signature_public_key);
  //console.log(typeof orderData.data.encrypt_public_keyy);
  //signature_public_key = crypto.createPublicKey(orderData.data.signature_public_key);
  //encrypt_public_key = crypto.createPublicKey(orderData.data.encrypt_public_ksey);
  //console.log(typeof signature_public_key);
  //console.log(typeof encrypt_public_ksey);
  signature_public_key = Buffer.from(orderData.data.signature_public_key);
  encrypt_public_key = Buffer.from(orderData.data.encrypt_public_key);
  var order_signature = orderData.signature.toString();
  //console.log('Sig from buyer: ',order_signature)
  //console.log('key used by buyer: ', signature_public_key)
  if(signature_required == 1){
    //console.log('check sig and key')
    //console.log(typeof order_signature)
    //console.log(typeof signature_public_key)
    var check = verifysignature(JSON.stringify(orderData.data),order_signature,signature_public_key);
    //console.log('check: ' + check)
    if(!check){
      console.log('*** !Wrong Signature! ***');
      //server.close()
    }else{
      console.log('Signature Matched!')
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
    console.log('*** Menu Sent ***');
  }

  function handleData(data){
    jsonData = JSON.parse(data);
    console.log('Received Data! Data Type: ',jsonData.message_type,' \n')

    if (jsonData.message_type == 'DATA_ACK'||jsonData.message_type == 'PAYMENT_ACK'){
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
    final_sent = false;
    sendSessionKey();
    dataTransfer(dataLine);
  }

  function sendSessionKey(){
    var secret_key_encrypted=crypto.publicEncrypt(encrypt_public_key,Buffer.from(secret_key));
    var key_info = prepareJSONstring('session_key', secret_key_encrypted,0,0);

    console.log(typeof secret_key)
    console.log('Session Key sent:  \n', secret_key.toString('hex'))
    conn.write(key_info);
  }
  async function dataTransfer(dataLine){
    //console.log(counter);
    if(counter <= quantity){
      data = {}
      data.data = lines[counter-1]
      data =JSON.stringify(data);
      data = encrypt(data, secret_key);
      signature = signData(data,key);
      //transaction_hash = None
      message_type = "DATA"
      transaction_hash = ''
      if (counter % payment_granularity == 0){
          remaining = remaining - payment_granularity
          data_invoice = "Sent: " + payment_granularity
          data_invoice += "\nCost: " + payment_granularity*cost
          console.log('*** Invoice recorded ***');
          sending_message = 'SDPP_DATA_INVOICE';
          transaction_hash = await iota.sendTranscation(sender_seed, recv_address, data_invoice);
          data['invoice'] = (payment_granularity*cost).toString();
          message_type = "DATA_INVOICE"
          console.log(transaction_hash)
      }

        json_string = prepareJSONstring(message_type, data,signature,transaction_hash)
        console.log('Data Sent # ',counter, ' : \n', json_string);
        conn.write(json_string);
        counter++;
      }else{
        var remain_granularity = (counter -1)%payment_granularity;
        //console.log(remain_granularity)
        if(remain_granularity > 0 && final_sent == false){
          remaining = remain_granularity;
          data_invoice = "Sent: " + payment_granularity
          data_invoice += "\nCost: " + payment_granularity*cost
          console.log('***Final invoice recorded***');
          sending_message = 'SDPP_DATA_INVOICE';
          transaction_hash = await iota.sendTranscation(sender_seed, recv_address, data_invoice);
          data['invoice'] = (payment_granularity*cost).toString();
          message_type = "DATA_INVOICE"
          console.log('Hash: ',transaction_hash)

          json_string = prepareJSONstring(message_type, data,signature,transaction_hash)
          //console.log('Data Sent: \n', json_string);
          conn.write(json_string);
          //counter++;
          final_sent = true;
        }

        console.log('Sent all data!');

        //conn.destroy();
      }

  }

}
