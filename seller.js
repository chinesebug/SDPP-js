/*
import socket
import sys
from thread import *
import Crypto.Hash.MD5 as MD5
import Crypto.PublicKey.RSA as RSA
from Crypto import Random
from Crypto.Cipher import AES
import base64
import os
import hashlib
import iota
import logging
import json
import pprint
*/

var net = require('net');
const iota = require('./iotaModule');
//var JsonSocket = require('json-socket');
const fs = require('fs');


var port = 8081;
var host = '127.0.0.1';

const sender_seed = 'RAHULRAHULRAHULRAHULRAHULRAHULRAHULRAHULRAHULRAHULRAHULRAHULRAHULRAHULRAHUL9RAHUL';
const recv_address ='HELLOWORLDHELLOWORLDHELLOWORLDHELLOWORLDHELLOWORLDHELLOWORLDHELLOWORLDHELLOWORLDD';

const signature_required = 1
const payment_granularity = 5
//const payment_address = iota_api.get_new_addresses(count=1)
//const payment_address = str(payment_address['addresses'][0].address)
const bs = 32

var menu
var orderData
var lines
var dataLine
var counter = 1;
var remaining;
/////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////
function prepareJSONstring(message_type, data){
  var json_data = {}

  json_data['message_type'] = message_type
  json_data['data'] = data


  return JSON.stringify(json_data);
}

function prepareMenuData(){
  var menu ={}
  rawdata = fs.readFileSync('menu.json');
  menu = JSON.parse(rawdata);
  console.log('existing menu: %s', JSON.stringify(menu,null, 2));

  //signature = signData(menu)
  return menu;
}

function getData(orderData){
  data_type = orderData.data.data_type;
  quantity = orderData.data.quantity;
  currency = orderData.data.currency;

  cost = menu.menu.data_type;
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
    menu = prepareMenuData();
    json_string = JSON.stringify(menu,null,2);
    conn.write(json_string);
    console.log('Menu Sent');
  }

  function handleData(data){
    jsonData = JSON.parse(data);
    console.log('ReceivedData',jsonData.message_type)

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
    console.log('Order Information: ',JSON.stringify(orderData,null,2));
    dataLine = getData(orderData);
    dataTransfer(dataLine);
  }

  function dataTransfer(dataLine){
    if(counter <= quantity){
      data = {}
      data['data'] = lines[counter-1]
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

        json_string = prepareJSONstring(message_type, data)
        console.log('Data Sent: ', json_string);
        conn.write(json_string);
        counter++;
      }else{
        console.log('Sent all data!');
        conn.destroy();
      }

  }

}

/*
prepareJSONstring(message_type, data, signature=None, verification=None){

    json_data = {}

    json_data['message_type'] = message_type;
    json_data['data'] = data;

    if (signature){
        json_data['signature'] = signature;
    }else {
        json_data['signature'] = "";
    }

    if (verification){
        json_data['verification'] = verification;
    }else {
        json_data['verification'] = "";
    }

    return json.dumps(json_data)
}
*/


/////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////
//prepareMenuData();

////////////////IOTA///////////
//var sending_message = "Hello World";
//iota.sendTranscation(sender_seed, recv_address, sending_message);
