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
	D_API( RtlReAllocateHeap );
	D_API( RtlAllocateHeap );
	D_API( RtlFreeHeap );
	D_API( _vsnprintf );
} API ;

/*!
 *
 * Purpose:
 *
 * Creates a "buffer" object to use. The "buffer"
 * pointer of the structure points to the payload
 * being appended to.
 *
!*/
PBUFFER BufferCreate( VOID )
{
	API	Api;

	HANDLE	Ntl = NULL;
	PBUFFER	Buf = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );

	Ntl = LoadLibraryA( "ntdll.dll" );

	if ( Ntl != NULL ) {
		Api.RtlReAllocateHeap = C_PTR( GetProcAddress( Ntl, "RtlReAllocateHeap" ) );
		Api.RtlAllocateHeap   = C_PTR( GetProcAddress( Ntl, "RtlAllocateHeap" ) );
		Api.RtlFreeHeap       = C_PTR( GetProcAddress( Ntl, "RtlFreeHeap" ) );
		Api._vsnprintf        = C_PTR( GetProcAddress( Ntl, "_vsnprintf" ) );

		/* Create buffer Object */
		if ( ( Buf = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( BUFFER ) ) ) != NULL ) {
		};
		FreeLibrary( Ntl );
	};
	
	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );

	/* Return */
	return Buf;
};

/*!
 *
 * Purpose:
 *
 * Extends a buffer to the specified length
 *
!*/
BOOL BufferExtend( _In_ PBUFFER Buffer, ULONG Length )
{
	API	Api;
	BUFFER	Buf;

	INT	Len = 0;
	BOOL	Ret = FALSE;
	HANDLE	Ntl = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Buf, sizeof( Buf ) );

	Ntl = LoadLibraryA( "ntdll.dll" );

	if ( Ntl != NULL ) {

		Api.RtlReAllocateHeap = C_PTR( GetProcAddress( Ntl, "RtlReAllocateHeap" ) );
		Api.RtlAllocateHeap   = C_PTR( GetProcAddress( Ntl, "RtlAllocateHeap" ) );
		Api.RtlFreeHeap       = C_PTR( GetProcAddress( Ntl, "RtlFreeHeap" ) );
		Api._vsnprintf        = C_PTR( GetProcAddress( Ntl, "_vsnprintf" ) );

		if ( Buffer->Buffer != NULL ) {
			Buf.Buffer = Api.RtlReAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, Buffer->Buffer, Buffer->Length + Length );
		} else {
			Buf.Buffer = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, Buffer->Length + Length );
		};

		if ( Buf.Buffer != NULL ) {
			/* Set the new pointer */
			Buffer->Buffer = C_PTR( Buf.Buffer );

			/* Set the new length */
			Buffer->Length = Buffer->Length + Length;

			/* Status */
			Ret = TRUE;
		};

		/* Dereference */
		FreeLibrary( Ntl );
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Buf, sizeof( Buf ) );

	/* Status */
	return Ret;
};

/*!
 *
 * Purpose:
 *
 * Appends a formated string to a buffer.
 *
!*/
BOOL BufferPrintf( _In_ PBUFFER Buffer, _In_ PCHAR Format, ... )
{
	API	Api;
	BUFFER	Buf;
	va_list	Lst;

	INT	Len = 0;
	BOOL	Ret = FALSE;
	HANDLE	Ntl = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Buf, sizeof( Buf ) );
	RtlSecureZeroMemory( &Lst, sizeof( Lst ) );

	/* Reference ntdll.dll */
	Ntl = LoadLibraryA( "ntdll.dll" );

	if ( Ntl != NULL ) {

		Api.RtlReAllocateHeap = C_PTR( GetProcAddress( Ntl, "RtlReAllocateHeap" ) );
		Api.RtlAllocateHeap   = C_PTR( GetProcAddress( Ntl, "RtlAllocateHeap" ) );
		Api.RtlFreeHeap       = C_PTR( GetProcAddress( Ntl, "RtlFreeHeap" ) );
		Api._vsnprintf        = C_PTR( GetProcAddress( Ntl, "_vsnprintf" ) );

		/* Get length of buffer */
		va_start( Lst, Format );
		Len = Api._vsnprintf( NULL, 0, Format, Lst );
		va_end( Lst );

		/* Create a buffer */
		if ( Buffer->Buffer != NULL ) {
			Buf.Buffer = Api.RtlReAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, Buffer->Buffer, Buffer->Length + Len );
		} else {
			Buf.Buffer = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, Buffer->Length + Len );
		};

		if ( Buf.Buffer != NULL ) {
			/* Set new pointer */
			Buffer->Buffer = C_PTR( Buf.Buffer );

			/* Copy over our buffer */
			va_start( Lst, Format );
			Len = Api._vsnprintf( C_PTR( U_PTR( Buffer->Buffer ) + Buffer->Length ), Len, Format, Lst );
			va_end( Lst );

			/* Set new length */
			Buffer->Length = Buffer->Length + Len;

			/* Status */
			Ret = TRUE;
		};

		/* Dereference */
		FreeLibrary( Ntl );
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Buf, sizeof( Buf ) );
	RtlSecureZeroMemory( &Lst, sizeof( Lst ) );

	/* Did our allocation succeed? */
	return Ret;
};
