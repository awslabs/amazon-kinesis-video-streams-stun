/* Standard includes. */
#include <stdint.h>
#include <stun_data_types.h>

#define SWAP_BYTES_16( value )          \
    ( ( ( ( value ) >> 8 ) & 0xFF ) |   \
      ( ( ( value ) & 0xFF ) << 8 ) )

#define SWAP_BYTES_32( value )          \
    ( ( ( ( value ) >> 24 ) & 0xFF ) |  \
      ( ( ( value ) >> 8 ) & 0xFF00 ) | \
      ( ( ( value ) & 0xFF00 ) << 8 ) | \
      ( ( ( value ) & 0xFF ) << 24 ) )

void writeUINT16Swap( uint8_t * pDst, uint16_t val )
{
    ( *( ( uint16_t * )( pDst ) ) = SWAP_BYTES_16( val ) );
}

void writeUINT32Swap( uint8_t * pDst, uint32_t val )
{
    ( *( ( uint32_t * )( pDst ) ) = SWAP_BYTES_32( val ) );
}

void readUINT16Swap( uint16_t * val, uint8_t * pSrc )
{
    ( ( * val ) = SWAP_BYTES_16( *( ( uint16_t * )( pSrc ) ) ) );
}

void readUINT32Swap( uint32_t * val, uint8_t * pSrc )
{
    ( ( * val ) = SWAP_BYTES_32( *( ( uint32_t * )( pSrc ) ) ) );
}

void writeUINT16NoSwap( uint8_t *pDst, uint16_t val )
{
    ( *( ( uint16_t * )( pDst ) ) = ( val ) );
}
void writeUINT32NoSwap( uint8_t *pDst, uint32_t val )
{
    ( *( ( uint32_t * )( pDst ) ) = ( val ) );
}
void readUINT16NoSwap( uint16_t * val, uint8_t *pSrc )
{
    ( ( * val ) = *( ( uint16_t * )( pSrc ) ) );
}
void readUINT32NoSwap( uint32_t * val, uint8_t *pSrc )
{
    ( ( * val ) = *( ( uint32_t * )( pSrc ) ) );
}

void init_endianness()
{
    uint8_t littleEndian;

    littleEndian = ( *( uint8_t * )( &( uint16_t ){ 1 } ) == 1 );

    if ( littleEndian )
    {
        writeUINT16 = writeUINT16Swap;
        writeUINT32 = writeUINT32Swap;
        readUINT16 = readUINT16Swap;
        readUINT32 = readUINT32Swap;
    }
    else
    {
        writeUINT16 = writeUINT16NoSwap;
        writeUINT32 = writeUINT32NoSwap;
        readUINT16 = readUINT16NoSwap;
        readUINT32 = readUINT32NoSwap;
    }
}