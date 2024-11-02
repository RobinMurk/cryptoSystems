#!/usr/bin/env python3

# do not use any other imports/libraries
import codecs
import datetime
import hashlib
import io
import sys
import zipfile

# apt-get install python3-bs4 python3-pyasn1-modules python3-m2crypto python3-lxml
import M2Crypto # type: ignore
import lxml.etree # type: ignore
from bs4 import BeautifulSoup # type: ignore
from pyasn1.codec.der import decoder, encoder # type: ignore
from pyasn1_modules import rfc2560 # type: ignore

# took 9 hours (please specify here how much time your solution required)

def verify_ecdsa(cert, signature_value, signed_hash):
    # verifies ECDSA signature given the hash value
    X509 = M2Crypto.X509.load_cert_der_string(cert)
    EC_pubkey = M2Crypto.EC.pub_key_from_der(X509.get_pubkey().as_der())

    # constructing r and s to satisfy M2Crypto
    l = len(signature_value)//2
    r = signature_value[:l]
    s = signature_value[l:]
    if r[0]>>7:
        r = b'\x00' + r
    if s[0]>>7:
        s = b'\x00' + s
    r = b'\x00\x00\x00' + bytes([len(r)]) + r
    s = b'\x00\x00\x00' + bytes([len(s)]) + s
    return EC_pubkey.verify_dsa(signed_hash, r, s)

def parse_tsa_response(timestamp_resp:bytes):
    # extracts from a TSA response the timestamp and timestamped DigestInfo
    timestamp = decoder.decode(timestamp_resp)
    tsinfo = decoder.decode(timestamp[0][1][2][1])[0]
    ts_digestinfo = encoder.encode(tsinfo[2])
    ts = datetime.datetime.strptime(str(tsinfo[4]), '%Y%m%d%H%M%SZ')
    # let's assume that the timestamp has been issued by a trusted TSA
    return ts, ts_digestinfo

def parse_ocsp_response(ocsp_resp:bytes):
    # extracts from an OCSP response certID_serial, certStatus and thisUpdate
    ocspResponse, _ = decoder.decode(ocsp_resp, asn1Spec=rfc2560.OCSPResponse())
    responseStatus = ocspResponse.getComponentByName('responseStatus')
    assert responseStatus == rfc2560.OCSPResponseStatus('successful'), responseStatus.prettyPrint()
    responseBytes = ocspResponse.getComponentByName('responseBytes')
    responseType = responseBytes.getComponentByName('responseType')
    assert responseType == rfc2560.id_pkix_ocsp_basic, responseType.prettyPrint()
    response = responseBytes.getComponentByName('response')
    basicOCSPResponse, _ = decoder.decode(response, asn1Spec=rfc2560.BasicOCSPResponse())
    tbsResponseData = basicOCSPResponse.getComponentByName('tbsResponseData')
    response0 = tbsResponseData.getComponentByName('responses').getComponentByPosition(0)
    # let's assume that the OCSP response has been signed by a trusted OCSP responder
    certID = response0.getComponentByName('certID')
    # let's assume that the issuer name and key hashes in certID are correct
    certID_serial = certID[3]
    certStatus = response0.getComponentByName('certStatus').getName()
    thisUpdate = datetime.datetime.strptime(str(response0.getComponentByName('thisUpdate')), '%Y%m%d%H%M%SZ')

    return certID_serial, certStatus, thisUpdate

def canonicalize(full_xml, tagname):
    # returns XML canonicalization of an element with the specified tagname
    if type(full_xml)!=bytes:
        print("[-] canonicalize(): input is not a bytes object containing XML:", type(full_xml))
        exit(1)
    input = io.BytesIO(full_xml)
    et = lxml.etree.parse(input)
    output = io.BytesIO()
    lxml.etree.ElementTree(et.find('.//{*}'+tagname)).write_c14n(output)
    return output.getvalue()

def get_subject_cn(cert_der):
    # returns CommonName value from the certificate's Subject Distinguished Name field
    # looping over Distinguished Name entries until CN found
    for rdn in decoder.decode(cert_der)[0][0][5]:
        if str(rdn[0][0]) == '2.5.4.3': # CommonName
            return str(rdn[0][1])
    return ''


def check_MIMETYPE_file_exists(archive: zipfile.ZipFile) -> bool:
    try:
        mimetype_file = archive.read('mimetype')
        mimetype = mimetype_file.decode()
        if(mimetype == "application/vnd.etsi.asic-e+zip"):
            return True
        else:
            print("[-] Wrong mimetype, failed check")
            exit(1)
    except Exception as error:
        print("[-] unknown error in checking mimetype: ", error)
        exit(1)

def check_DataObjFormat_MIMETYPE(xmldoc:BeautifulSoup) -> bool:
    try:
        data_obj_format = xmldoc.XAdESSignatures.Object.QualifyingProperties.SignedProperties.DataObjectFormat.MimeType.encode_contents()
        if(data_obj_format != b''):
            return True
        else:
            print("[-] Could not locate mimetype in DataObjectFormat tag")
            exit(1)
    except Exception as error:
        print("[-] Unknown error in checking if DataObjFormat exists: ", error)
        exit(1)

def check_source_file_digest_value(archive:zipfile.ZipFile, xmldoc:BeautifulSoup) -> bool:
    try:
        file_name = xmldoc.XAdESSignatures.Signature.SignedInfo.Reference['URI']
        source_file = archive.read(file_name)
        calculated_digest = hashlib.sha256(source_file).digest()
        given_digest = codecs.decode(xmldoc.XAdESSignatures.SignedInfo.find('Reference',attrs={'Id': 'S0-RefId1'}).DigestValue.encode_contents(),'base64')
        if(calculated_digest == given_digest):
            return True
        else:
            print("[-] source file digest is invalid")
            exit(1)

    except Exception as error:
        print("[-] Unknown error occured during source file digest value validation: ", error)
        exit(1)

def check_x509_certificate_digest_value(xmldoc:BeautifulSoup) -> bool:
    try:
        x509_cert = xmldoc.XAdESSignatures.KeyInfo.X509Data.X509Certificate.encode_contents()
        x509_cert = codecs.decode(x509_cert,'base64')
        x509_digest = hashlib.sha256(x509_cert).digest()
        x509_digest = codecs.encode(x509_digest,'base64').strip()
        x509_given = xmldoc.XAdESSignatures.Signature.Object.CertDigest.DigestValue.encode_contents()
        if(x509_digest == x509_given):
            return True
        else:
            print("[-] x509 hashes dont match")
            exit(1)

    except Exception as error:
        print("[-] unknown error when validating x509 certificate: ", error)
        exit(1)
    
def check_signed_properties_digest_value(xml: bytes, xmldoc:BeautifulSoup) -> bool:
    try:
        signed_properties = canonicalize(xml,"SignedProperties")
        signed_properties_digest = codecs.encode(hashlib.sha256(signed_properties).digest(), 'base64').strip()
        digest_given = xmldoc.XAdESSignatures.Signature.SignedInfo.find('Reference',attrs={'URI': '#S0-SignedProperties'}).DigestValue.encode_contents() #base64
        if (signed_properties_digest == digest_given):
            return True
        else:
            print("[-] digests for signed properties do not match")
            exit(1)
    except Exception as error:
        print("[-] unknown error when validating signed properties digest: ", error)
        exit(1)

def check_certIDserial_toX509SerialNumber(certID_serial, xmldoc:BeautifulSoup) -> bool:
    try:
        x509_serial_number = xmldoc.XAdESSignatures.Signature.SignedProperties.IssuerSerial.X509SerialNumber.encode_contents()
        if (int(certID_serial) == int(x509_serial_number)):
            return True
        else:
            print("[-] certID serial numbers do not match")
            exit(1)
    except Exception as error:
        print("[-] unknown error when validating certID serial: ", error)
        exit(1)

def check_TSA_and_OCSP_thisUpdate(TSA_time:datetime,OCSP_time:datetime) -> bool:
    if(TSA_time < OCSP_time):
        return True
    else:
        print("[-] OCSP certificate was not valid during the signing process")
        exit(1)

def check_TSA_signature_value_to_SignatureValue(tsa_digest,xml) -> bool:
    try:
        signature_value_given = canonicalize(xml,'SignatureValue')
        signature_value_given = hashlib.sha256(signature_value_given).digest()

        tsa_signature = decoder.decode(tsa_digest)
        tsa_signature = tsa_signature[0][1].asOctets()
        if (tsa_signature == signature_value_given):
            return True
        else:
            print("[-] wrong signee in TSA response")
            exit(1)
    except Exception as error:
        print("[-] unknown error when validating TSA signee signature: ", error)
        exit(1)

filename = sys.argv[1]

# get and decode XML
archive = zipfile.ZipFile(filename, 'r')
xml = archive.read('META-INF/signatures0.xml')
xmldoc = BeautifulSoup(xml,features="xml")

# let's trust this certificate
signers_cert_der = codecs.decode(xmldoc.XAdESSignatures.KeyInfo.X509Data.X509Certificate.encode_contents(), 'base64')
print("[+] Signatory:", get_subject_cn(signers_cert_der))


encapsulated_timestamp = xmldoc.XAdESSignatures.Object.UnsignedProperties.EncapsulatedTimeStamp.encode_contents()
ts, ts_digest_info = parse_tsa_response(codecs.decode(encapsulated_timestamp,'base64'))
certID_serial, certStatus, thisUpdate = parse_ocsp_response(codecs.decode(xmldoc.XAdESSignatures.Object.UnsignedProperties.OCSPValues.EncapsulatedOCSPValue.encode_contents(),'base64'))

print("[+] Timestamped: %s +00:00" % (ts))

file_name = xmldoc.XAdESSignatures.Signature.SignedInfo.Reference['URI']
print("[+] Signed file: ",file_name)


if(certStatus != "good"):
    print("[-] signers certificate is not valid")
    exit(1)


#extra checks
check_MIMETYPE_file_exists(archive)
check_DataObjFormat_MIMETYPE(xmldoc)
check_source_file_digest_value(archive,xmldoc)
check_x509_certificate_digest_value(xmldoc)
check_signed_properties_digest_value(xml, xmldoc)
check_certIDserial_toX509SerialNumber(certID_serial=certID_serial,xmldoc=xmldoc)
check_TSA_and_OCSP_thisUpdate(ts,thisUpdate)
check_TSA_signature_value_to_SignatureValue(ts_digest_info,xml)

signed_info_str = canonicalize(xml,"SignedInfo")
signature_value = codecs.decode(xmldoc.XAdESSignatures.Signature.SignatureValue.encode_contents(),'base64')

# finally verify signatory's signature
if verify_ecdsa(signers_cert_der, signature_value, hashlib.sha384(signed_info_str).digest()):
    print("[+] Signature verification successful!")
else:
    print("[-] Signature verification failure!")
