/* API includes. */
#include "stun_endianness.h"

#define SWAP_BYTES_16( value )          \
    ( ( ( ( value ) >> 8 ) & 0xFF ) |   \
      ( ( ( value ) & 0xFF ) << 8 ) )

#define SWAP_BYTES_32( value )           \
    ( ( ( ( value ) >> 24 ) & 0xFF )  |  \
      ( ( ( value ) >> 8 ) & 0xFF00 ) |  \
      ( ( ( value ) & 0xFF00 ) << 8 ) |  \
      ( ( ( value ) & 0xFF ) << 24 ) )

#define SWAP_BYTES_64( value )                              \
    ( ( ( ( uint64_t )( value ) >> 56 ) & 0xFF )        |   \
      ( ( ( uint64_t )( value ) >> 40 ) & 0xFF00 )      |   \
      ( ( ( uint64_t )( value ) >> 24 ) & 0xFF0000 )    |   \
      ( ( ( uint64_t )( value ) >> 8 ) & 0xFF000000 )   |   \
      ( ( ( uint64_t )( value ) & 0xFF000000 ) << 8 )   |   \
      ( ( ( uint64_t )( value ) & 0xFF0000 ) << 24 )    |   \
      ( ( ( uint64_t )( value ) & 0xFF00 ) << 40 )      |   \
      ( ( ( uint64_t )( value ) & 0xFF ) << 56 ) )

/*-----------------------------------------------------------*/

void WriteUint16Swap( uint8_t * pDst, uint16_t val )
{
    *( ( uint16_t * )( pDst ) ) = SWAP_BYTES_16( val );
}

/*-----------------------------------------------------------*/

void WriteUint32Swap( uint8_t * pDst, uint32_t val )
{
    *( ( uint32_t * )( pDst ) ) = SWAP_BYTES_32( val );
}

/*-----------------------------------------------------------*/

void WriteUint64Swap( uint8_t * pDst, uint64_t val )
{
    *( ( uint64_t * )( pDst ) ) = SWAP_BYTES_64( val );
}

/*-----------------------------------------------------------*/

uint16_t ReadUint16Swap( const uint8_t * pSrc )
{
    return SWAP_BYTES_16( *( ( uint16_t * )( pSrc ) ) );
}

/*-----------------------------------------------------------*/

uint32_t ReadUint32Swap( const uint8_t * pSrc )
{
    return SWAP_BYTES_32( *( ( uint32_t * )( pSrc ) ) );
}

/*-----------------------------------------------------------*/

uint64_t ReadUint64Swap( const uint8_t * pSrc )
{
    return SWAP_BYTES_64( *( ( uint64_t * )( pSrc ) ) );
}

/*-----------------------------------------------------------*/

void WriteUint16NoSwap( uint8_t * pDst, uint16_t val )
{
    *( ( uint16_t * )( pDst ) ) = ( val );
}

/*-----------------------------------------------------------*/

void WriteUint32NoSwap( uint8_t * pDst, uint32_t val )
{
    *( ( uint32_t * )( pDst ) ) = ( val );
}

/*-----------------------------------------------------------*/

void WriteUint64NoSwap( uint8_t * pDst, uint64_t val )
{
    *( ( uint64_t * )( pDst ) ) = ( val );
}

/*-----------------------------------------------------------*/

uint16_t ReadUint16NoSwap( const uint8_t * pSrc )
{
    return *( ( uint16_t * )( pSrc ) );
}

/*-----------------------------------------------------------*/

uint32_t ReadUint32NoSwap( const uint8_t * pSrc )
{
    return *( ( uint32_t * )( pSrc ) );
}

/*-----------------------------------------------------------*/

uint64_t ReadUint64NoSwap( const uint8_t * pSrc )
{
    return *( ( uint64_t * )( pSrc ) );
}

/*-----------------------------------------------------------*/

void Stun_InitReadWriteFunctions( StunReadWriteFunctions_t * pReadWriteFunctions )
{
    uint8_t isLittleEndian;

    isLittleEndian = ( *( uint8_t * )( &( uint16_t ){ 1 } ) == 1 );

    if( isLittleEndian != 0 )
    {
        pReadWriteFunctions->writeUint16Fn = WriteUint16Swap;
        pReadWriteFunctions->writeUint32Fn = WriteUint32Swap;
        pReadWriteFunctions->writeUint64Fn = WriteUint64Swap;
        pReadWriteFunctions->readUint16Fn = ReadUint16Swap;
        pReadWriteFunctions->readUint32Fn = ReadUint32Swap;
        pReadWriteFunctions->readUint64Fn = ReadUint64Swap;
    }
    else
    {
        pReadWriteFunctions->writeUint16Fn = WriteUint16NoSwap;
        pReadWriteFunctions->writeUint32Fn = WriteUint32NoSwap;
        pReadWriteFunctions->writeUint64Fn = WriteUint64NoSwap;
        pReadWriteFunctions->readUint16Fn = ReadUint16NoSwap;
        pReadWriteFunctions->readUint32Fn = ReadUint32NoSwap;
        pReadWriteFunctions->readUint64Fn = ReadUint64NoSwap;
    }
}

/*-----------------------------------------------------------*/
