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

#define SWAP_BYTES_64(value)                             \
    ( ( ( (uint64_t)(value) >> 56 ) & 0xFF ) |           \
      ( ( (uint64_t)(value) >> 40 ) & 0xFF00 ) |         \
      ( ( (uint64_t)(value) >> 24 ) & 0xFF0000 ) |       \
      ( ( (uint64_t)(value) >> 8 ) & 0xFF000000 ) |      \
      ( ( (uint64_t)(value) & 0xFF000000 ) << 8 ) |      \
      ( ( (uint64_t)(value) & 0xFF0000 ) << 24 ) |       \
      ( ( (uint64_t)(value) & 0xFF00 ) << 40 ) |         \
      ( ( (uint64_t)(value) & 0xFF ) << 56 ) )

void ( *writeUINT16 ) ( uint8_t *, uint16_t );
void ( *writeUINT32 ) ( uint8_t *, uint32_t );
void ( *writeUINT64 ) ( uint8_t *, uint64_t );
void ( *readUINT16 ) ( uint16_t *, uint8_t * );
void ( *readUINT32 ) ( uint32_t *, uint8_t * );
void ( *readUINT64 ) ( uint64_t *, uint8_t * );

void writeUINT16Swap( uint8_t * pDst, uint16_t val )
{
    ( *( ( uint16_t * )( pDst ) ) = SWAP_BYTES_16( val ) );
}

void writeUINT32Swap( uint8_t * pDst, uint32_t val )
{
    ( *( ( uint32_t * )( pDst ) ) = SWAP_BYTES_32( val ) );
}

void writeUINT64Swap( uint8_t * pDst, uint64_t val )
{
    ( *( ( uint64_t * )( pDst ) ) = SWAP_BYTES_64( val ) );
}

void readUINT16Swap( uint16_t * val, uint8_t * pSrc )
{
    ( ( * val ) = SWAP_BYTES_16( *( ( uint16_t * )( pSrc ) ) ) );
}

void readUINT32Swap( uint32_t * val, uint8_t * pSrc )
{
    ( ( * val ) = SWAP_BYTES_32( *( ( uint32_t * )( pSrc ) ) ) );
}

void readUINT64Swap( uint64_t * val, uint8_t * pSrc )
{
    ( ( * val ) = SWAP_BYTES_64( *( ( uint64_t * )( pSrc ) ) ) );
}

void writeUINT16NoSwap( uint8_t *pDst, uint16_t val )
{
    ( *( ( uint16_t * )( pDst ) ) = ( val ) );
}
void writeUINT32NoSwap( uint8_t *pDst, uint32_t val )
{
    ( *( ( uint32_t * )( pDst ) ) = ( val ) );
}
void writeUINT64NoSwap( uint8_t *pDst, uint64_t val )
{
    ( *( ( uint64_t * )( pDst ) ) = ( val ) );
}
void readUINT16NoSwap( uint16_t * val, uint8_t *pSrc )
{
    ( ( * val ) = *( ( uint16_t * )( pSrc ) ) );
}
void readUINT32NoSwap( uint32_t * val, uint8_t *pSrc )
{
    ( ( * val ) = *( ( uint32_t * )( pSrc ) ) );
}
void readUINT64NoSwap( uint64_t * val, uint8_t *pSrc )
{
    ( ( * val ) = *( ( uint64_t * )( pSrc ) ) );
}

void init_endianness()
{
    uint8_t littleEndian;

    littleEndian = ( *( uint8_t * )( &( uint16_t ){ 1 } ) == 1 );

    if ( littleEndian )
    {
        writeUINT16 = writeUINT16Swap;
        writeUINT32 = writeUINT32Swap;
        writeUINT64 = writeUINT64Swap;
        readUINT16 = readUINT16Swap;
        readUINT32 = readUINT32Swap;
        readUINT64 = readUINT64Swap;
    }
    else
    {
        writeUINT16 = writeUINT16NoSwap;
        writeUINT32 = writeUINT32NoSwap;
        writeUINT64 = writeUINT64NoSwap;
        readUINT16 = readUINT16NoSwap;
        readUINT32 = readUINT32NoSwap;
        readUINT64 = readUINT64NoSwap;
    }
}