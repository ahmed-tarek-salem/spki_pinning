import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

import 'exceptions.dart';

// --- DER in ten lines --------------------------------------------------
// DER encodes every value as a TLV: one Tag byte, a Length, then Content.
//   length byte < 0x80     -> that byte IS the content length (short form).
//   length byte 0x81..0x84 -> the next 1..4 bytes hold the length,
//                             big-endian (long form).
//   length byte == 0x80    -> "indefinite length": legal in BER, illegal
//                             in DER — always rejected here.
// A certificate is nested TLVs with a field order frozen by RFC 5280:
//   Certificate ::= SEQUENCE {
//     tbsCertificate ::= SEQUENCE {
//       [0] version (optional), serialNumber, signature, issuer,
//       validity, subject, subjectPublicKeyInfo, ...
//     },
//     signatureAlgorithm, signatureValue }
// So reaching the SPKI needs no X.509 parsing: enter two SEQUENCEs, skip
// the optional [0], skip five fields, and the next TLV is the SPKI.
// -----------------------------------------------------------------------

/// ASN.1 tag for SEQUENCE.
const _tagSequence = 0x30;

/// ASN.1 tag for INTEGER.
const _tagInteger = 0x02;

/// Context tag `[0]`: the optional TBSCertificate `version` field,
/// present in v2/v3 certificates and absent in v1.
const _tagVersion = 0xa0;

class _Tlv {
  _Tlv(this.tag, this.headerStart, this.contentStart, this.contentLength);

  final int tag;
  final int headerStart;
  final int contentStart;
  final int contentLength;

  int get end => contentStart + contentLength;
}

_Tlv _readTlv(Uint8List der, int offset) {
  if (offset < 0 || offset + 2 > der.length) {
    throw SpkiParseException('unexpected end of DER at offset $offset');
  }
  final tag = der[offset];
  var pos = offset + 1;
  final first = der[pos++];
  int length;
  if (first < 0x80) {
    length = first;
  } else if (first == 0x80) {
    throw SpkiParseException('indefinite length is illegal in DER');
  } else {
    final numBytes = first & 0x7f;
    if (numBytes > 4) {
      throw SpkiParseException('unsupported length-of-length $numBytes');
    }
    if (pos + numBytes > der.length) {
      throw SpkiParseException('truncated long-form length');
    }
    length = 0;
    for (var i = 0; i < numBytes; i++) {
      length = (length << 8) | der[pos++];
    }
  }
  if (pos + length > der.length) {
    throw SpkiParseException('TLV content overruns buffer');
  }
  return _Tlv(tag, offset, pos, length);
}

/// Extracts the complete DER bytes (header + content) of the
/// `subjectPublicKeyInfo` field from an X.509 certificate.
///
/// This is a TLV *skipper*, not an X.509 parser: DER is deterministic and
/// RFC 5280 freezes the TBSCertificate field order, so only tag+length
/// headers are read and fields are skipped without interpreting their
/// contents. Any structural anomaly throws [SpkiParseException].
Uint8List extractSpkiDer(Uint8List certificateDer) {
  final cert = _readTlv(certificateDer, 0);
  if (cert.tag != _tagSequence) {
    throw SpkiParseException('certificate is not a SEQUENCE');
  }
  final tbs = _readTlv(certificateDer, cert.contentStart);
  if (tbs.tag != _tagSequence) {
    throw SpkiParseException('tbsCertificate is not a SEQUENCE');
  }
  var next = _readTlv(certificateDer, tbs.contentStart);
  if (next.tag == _tagVersion) {
    next = _readTlv(certificateDer, next.end);
  }
  const expectedTags = [
    _tagInteger, // serialNumber
    _tagSequence, // signature (AlgorithmIdentifier)
    _tagSequence, // issuer
    _tagSequence, // validity
    _tagSequence, // subject
  ];
  for (final tag in expectedTags) {
    if (next.tag != tag) {
      throw SpkiParseException(
          'unexpected tag 0x${next.tag.toRadixString(16)} in TBSCertificate '
          '(expected 0x${tag.toRadixString(16)})');
    }
    if (next.end > tbs.end) {
      throw SpkiParseException('field overruns TBSCertificate');
    }
    next = _readTlv(certificateDer, next.end);
  }
  if (next.tag != _tagSequence) {
    throw SpkiParseException('subjectPublicKeyInfo is not a SEQUENCE');
  }
  if (next.end > tbs.end) {
    throw SpkiParseException('subjectPublicKeyInfo overruns TBSCertificate');
  }
  return Uint8List.fromList(
      Uint8List.sublistView(certificateDer, next.headerStart, next.end));
}

/// SHA-256 pin of the certificate's SPKI, formatted `sha256/<base64>`.
String spkiPinOf(Uint8List certificateDer) {
  final digest = sha256.convert(extractSpkiDer(certificateDer));
  return 'sha256/${base64.encode(digest.bytes)}';
}
