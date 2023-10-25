import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

// ignore: depend_on_referenced_packages
import 'package:crypto/crypto.dart';
import 'package:encrypt/encrypt.dart' as encrypt;
import 'package:flutter/material.dart';
import 'package:tuple/tuple.dart';

class AES {
  static String encryptAES({
    String? plainText,
    String? password,
  }) {
    try {
      final salt = genRandomWithNonZero(8);
      var keyndIV = deriveKeyAndIV(
        password!,
        salt,
      );
      final key = encrypt.Key(keyndIV.item1);
      final iv = encrypt.IV(keyndIV.item2);
      final encrypter = encrypt.Encrypter(
        encrypt.AES(
          key,
          mode: encrypt.AESMode.cbc,
          padding: "PKCS7",
        ),
      );
      final encrypted = encrypter.encrypt(
        plainText!,
        iv: iv,
      );
      Uint8List encryptedBytesWithSalt = Uint8List.fromList(
          createUnit8ListFromString("Salted__") + salt + encrypted.bytes);
      return base64.encode(encryptedBytesWithSalt);
    } catch (error) {
      rethrow;
    }
  }

  static String decryptAES({
    String? encrypted,
    String? password,
  }) {
    try {
      Uint8List encryptedBytesWithSalt = base64.decode(encrypted!);
      Uint8List encryptedBytes = encryptedBytesWithSalt.sublist(
        16,
        encryptedBytesWithSalt.length,
      );
      final salt = encryptedBytesWithSalt.sublist(
        8,
        16,
      );
      var keyNdIV = deriveKeyAndIV(
        password!,
        salt,
      );
      final key = encrypt.Key(keyNdIV.item1);
      final iv = encrypt.IV(keyNdIV.item2);
      final encrypter = encrypt.Encrypter(
        encrypt.AES(
          key,
          mode: encrypt.AESMode.cbc,
          padding: "PKCS7",
        ),
      );
      final decrypted =
          encrypter.decrypt64(base64.encode(encryptedBytes), iv: iv);
      return decrypted;
    } catch (error) {
      rethrow;
    }
  }

  static Tuple2<Uint8List, Uint8List> deriveKeyAndIV(
      String passphrase, Uint8List salt) {
    var password = createUnit8ListFromString(passphrase);
    Uint8List concatenatedHashes = Uint8List(0);
    Uint8List currentHash = Uint8List(0);
    bool enoughBytesForKey = false;
    Uint8List preHash = Uint8List(0);
    while (!enoughBytesForKey) {
      if (currentHash.isNotEmpty) {
        preHash = Uint8List.fromList(currentHash + password + salt);
      } else {
        preHash = Uint8List.fromList(password + salt);
      }
      currentHash = Uint8List.fromList(md5.convert(preHash).bytes);
      concatenatedHashes = Uint8List.fromList(concatenatedHashes + currentHash);
      if (concatenatedHashes.length >= 48) enoughBytesForKey = true;
    }
    var keyBytes = concatenatedHashes.sublist(
      0,
      32,
    );
    var ivBytes = concatenatedHashes.sublist(
      32,
      48,
    );
    return Tuple2(keyBytes, ivBytes);
  }

  static Uint8List createUnit8ListFromString(String s) {
    var ret = Uint8List(s.length);
    for (var i = 0; i < s.length; i++) {
      ret[i] = s.codeUnitAt(i);
    }
    return ret;
  }

  static Uint8List genRandomWithNonZero(int seedLength) {
    final random = Random.secure();
    const int randomMax = 245;
    final Uint8List unit8list = Uint8List(seedLength);
    for (int i = 0; i < seedLength; i++) {
      unit8list[i] = random.nextInt(randomMax) + 1;
    }
    return unit8list;
  }
}

