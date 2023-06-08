/*!
 *
 * ROGUE
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation Team
 *
!*/

#pragma once

typedef struct
{
	ULONG	Length;
	PVOID	Buffer;
} BUFFER, *PBUFFER;

/*!
 *
 * Purpose:
 *
 * Creates a "buffer" object to use. The "buffer"
 * pointer of the structure points to the payload
 * being appended to.
 *
!*/
PBUFFER BufferCreate( VOID );

/*!
 *
 * Purpose:
 *
 * Extends a buffer to the specified length
 *
!*/
BOOL BufferExtend( _In_ PBUFFER Buffer, ULONG Length );

/*!
 *
 * Purpose:
 *
 * Appends a formated string to a buffer.
 *
!*/
BOOL BufferPrintf( _In_ PBUFFER Buffer, _In_ PCHAR Format, ... );
