import 'package:flutter/material.dart';

import 'encryptAES_decryptAES.dart';

void main() {
 // runApp(const MaterialApp(home:Unit() ,) );

  String a = AES.encryptAES(
    plainText: "Denish1@gmail.com",
    password: "1234",
  );
  String c = AES.encryptAES(
    plainText: "1234pass",
    password: "1234",

  );
  String d = AES.decryptAES(
    encrypted:  a,
    password: "1234",
  );
  String e = AES.decryptAES(
    encrypted: c,
    password: "1234",
  );


  print("---------------------${d}");
  print("---------------------${e}");

}


