#!/usr/bin/env python3
# -*- coding:utf-8 -*-
import argparse
import struct
import os
from pyasn1.codec.der import decoder, encoder
from lib.utils.spnego import GSSAPIHeader_KRB5_AP_REQ
from lib.utils.krbcredccache import KrbCredCCache
from impacket.krb5.crypto import Key, _enctype_table
from impacket.krb5.asn1 import Authenticator, KRB_CRED, EncKrbCredPart

def dir_type( string ):
    if os.path.isdir( string ):
        return string
    else:
        raise NotADirectoryError( string )

if __name__ in '__main__':
    parser = argparse.ArgumentParser( description = 'Extracts a CCACHE from the apreq and session key files.' );
    parser.add_argument( 'apreq', type = argparse.FileType( 'rb+' ), help = 'Path to the apreq buffer retrieved from krbtgs' );
    parser.add_argument( 'key', type = argparse.FileType( 'rb+' ), help = 'Path to the session key retrieved from krbtgs' );
    parser.add_argument( 'encryption_type', choices = [ 'aes256', 'aes128', 'rc4' ] );
    parser.add_argument( 'folder', type = dir_type, help = 'Path to save the extracted tickets to.' );
    option = parser.parse_args();

    # attempt to extract the ticket
    try:
        krbbuf = decoder.decode( option.apreq.read(), asn1Spec=GSSAPIHeader_KRB5_AP_REQ())[ 0 ]
    except Exception as e:
        raise Exception( 'Could not extract kerberos data.' );

    # extract the tgs
    tgs = krbbuf['apReq']
    
    # create key object
    if option.encryption_type == 'aes256':
        key = Key( 18, option.key.read() );
    elif option.encryption_type == 'aes128':
        key = Key( 17, option.key.read() );
    elif option.encryption_type == 'rc4':
        key = Key( 23, option.key.read() );

    # decrypt the Authenticator
    cip = _enctype_table[int(tgs['authenticator']['etype' ])]
    ptx = cip.decrypt(key, 11, tgs['authenticator']['cipher'] );
    aut = decoder.decode(ptx, asn1Spec=Authenticator())[ 0 ];
    if aut['cksum']['cksumtype'] != 32771:
        raise Exception( 'Checksum is not KRB5 type: %d' % aut['cksum']['cksumtype'] );

    # extract credentials
    buf = bytes(aut['cksum']['checksum'] )[28:28+struct.unpack('<H', bytes(aut['cksum']['checksum'])[26:28])[0] ]
    crd = decoder.decode( buf, asn1Spec=KRB_CRED())[ 0 ];
    cip = _enctype_table[int(crd['enc-part']['etype'])]
    ptx = cip.decrypt(key, 14, bytes(crd['enc-part']['cipher']));
    enc = decoder.decode( ptx, asn1Spec = EncKrbCredPart() )[ 0 ];

    # extract ticket information
    for idx, inf in enumerate( enc['ticket-info'] ):
        usr = '/'.join([str(itm) for itm in inf['pname']['name-string']] )
        rlm = str( inf['prealm'] );
        cch = KrbCredCCache()
        cch.fromKrbCredTicket( crd['tickets'][idx], inf );

        print( 'Saving ticket as {}@{} in {}'.format( usr, rlm, option.folder ) );
        cch.saveFile( '{}/{}@{}.ccache'.format( option.folder, usr, rlm ) );

