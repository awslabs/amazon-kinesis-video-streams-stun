#ifndef STUN_ENDIANNESS_H
#define STUN_ENDIANNESS_H

/* Standard includes. */
#include <stdint.h>

/* Endianness Function types. */
typedef void ( * WriteUint16_t ) ( uint8_t * pDst, uint16_t val );
typedef void ( * WriteUint32_t ) ( uint8_t * pDst, uint32_t val );
typedef void ( * WriteUint64_t ) ( uint8_t * pDst, uint64_t val );
typedef uint16_t ( * ReadUint16_t ) ( const uint8_t * pSrc );
typedef uint32_t ( * ReadUint32_t ) ( const uint8_t * pSrc );
typedef uint64_t ( * ReadUint64_t ) ( const uint8_t * pSrc );

typedef struct StunReadWriteFunctions
{
    WriteUint16_t writeUint16Fn;
    WriteUint32_t writeUint32Fn;
    WriteUint64_t writeUint64Fn;
    ReadUint16_t readUint16Fn;
    ReadUint32_t readUint32Fn;
    ReadUint64_t readUint64Fn;
} StunReadWriteFunctions_t;

void Stun_InitReadWriteFunctions( StunReadWriteFunctions_t * pReadWriteFunctions );

#endif /* STUN_ENDIANNESS_H */
