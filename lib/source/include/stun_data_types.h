#ifndef STUN_DATA_TYPES_H
#define STUN_DATA_TYPES_H

/* Standard includes. */
#include <stdint.h>
#include <stddef.h>

/*
 * STUN Message Header:
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |0 0|     STUN Message Type     |         Message Length        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                         Magic Cookie                          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * |                     Transaction ID (96 bits)                  |
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

/* Length and offsets of various members in the STUN header. */
#define STUN_HEADER_LENGTH                  20
#define STUN_HEADER_MESSAGE_LENGTH_OFFSET   2
#define STUN_HEADER_MAGIC_COOKIE_OFFSET     4
#define STUN_HEADER_TRANSACTION_ID_OFFSET   8
#define STUN_HEADER_TRANSACTION_ID_LENGTH   12

/* Cookie value in the header. */
#define STUN_HEADER_MAGIC_COOKIE        0x2112A442

/*
 * STUN Attribute:
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |         Type                  |            Length             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                         Value (variable)                ....
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

/* Length and offsets of various members in a STUN attribute. */
#define STUN_ATTRIBUTE_HEADER_LENGTH            4
#define STUN_ATTRIBUTE_HEADER_LENGTH_OFFSET     2
#define STUN_ATTRIBUTE_HEADER_VALUE_OFFSET      4
#define STUN_ATTRIBUTE_ADDRESS_HEADER_LENGTH    4

/* Helper macros. */
#define ALIGN_SIZE_TO_WORD( size )                  ( ( ( size ) + 0x3 ) & ~( 0x3 ) )
#define REMAINING_LENGTH( pCtx )                    ( ( pCtx )->totalLength - ( pCtx )->currentIndex )
#define STUN_ATTRIBUTE_TOTAL_LENGTH( valueLength )  ( valueLength + STUN_ATTRIBUTE_HEADER_LENGTH )

/* IP address macros */
#define STUN_ADDRESS_IPv4           0x01
#define STUN_ADDRESS_IPv6           0x02

#define STUN_IPV4_ADDRESS_SIZE      0x04
#define STUN_IPV6_ADDRESS_SIZE      0x10

/* STUN context flags. */
#define STUN_FLAG_FINGERPRINT_ATTRIBUTE             ( 1 << 0 )
#define STUN_FLAG_INTEGRITY_ATTRIBUTE               ( 1 << 1 )

/* Read/Write flags. */
#define WRITE_UINT16 ( *writeUINT16 )
#define WRITE_UINT32 ( *writeUINT32 )
#define READ_UINT16 ( *readUINT16 )
#define READ_UINT32 ( *readUINT32 )

void ( *writeUINT16 ) ( uint8_t *, uint16_t );
void ( *writeUINT32 ) ( uint8_t *, uint32_t );
void ( *readUINT16 ) ( uint16_t *, uint8_t * );
void ( *readUINT32 ) ( uint32_t *, uint8_t * );

void init_endianness();

/*-----------------------------------------------------------*/

typedef enum StunResult
{
    STUN_RESULT_OK,
    STUN_RESULT_BAD_PARAM,
    STUN_RESULT_OUT_OF_MEMORY,
    STUN_RESULT_MALFORMED_MESSAGE,
    STUN_RESULT_MAGIC_COOKIE_MISMATCH,
    STUN_RESULT_NO_MORE_ATTRIBUTE_FOUND,
    STUN_RESULT_INVALID_ATTRIBUTE_LENGTH,
    STUN_RESULT_INVALID_ATTRIBUTE_ORDER
} StunResult_t;

typedef enum StunMessageType
{
    STUN_MESSAGE_TYPE_BINDING_REQUEST           = 0x0001,
    STUN_MESSAGE_TYPE_BINDING_SUCCESS_RESPONSE  = 0x0101,
    STUN_MESSAGE_TYPE_BINDING_FAILURE_RESPONSE  = 0x0111,
    STUN_MESSAGE_TYPE_BINDING_INDICATION        = 0x0011
} StunMessageType_t;

typedef enum StunAttributeType
{
    STUN_ATTRIBUTE_TYPE_MAPPED_ADDRESS      = 0x0001,
    STUN_ATTRIBUTE_TYPE_RESPONSE_ADDRESS    = 0x0002,
    STUN_ATTRIBUTE_TYPE_SOURCE_ADDRESS      = 0x0004,
    STUN_ATTRIBUTE_TYPE_CHANGED_ADDRESS     = 0x0005,
    STUN_ATTRIBUTE_TYPE_USERNAME            = 0x0006,
    STUN_ATTRIBUTE_TYPE_MESSAGE_INTEGRITY   = 0x0008,
    STUN_ATTRIBUTE_TYPE_ERROR_CODE          = 0x0009,
    STUN_ATTRIBUTE_TYPE_REFLECTED_FROM      = 0x000B,
    STUN_ATTRIBUTE_TYPE_LIFETIME            = 0x000D,
    STUN_ATTRIBUTE_TYPE_XOR_PEER_ADDRESS    = 0x0012,
    STUN_ATTRIBUTE_TYPE_DATA                = 0x0013,
    STUN_ATTRIBUTE_TYPE_REALM               = 0x0014,
    STUN_ATTRIBUTE_TYPE_NONCE               = 0x0015,
    STUN_ATTRIBUTE_TYPE_XOR_RELAYED_ADDRESS = 0x0016,
    STUN_ATTRIBUTE_TYPE_REQUESTED_TRANSPORT = 0x0019,
    STUN_ATTRIBUTE_TYPE_XOR_MAPPED_ADDRESS  = 0x0020,
    STUN_ATTRIBUTE_TYPE_PRIORITY            = 0x0024,
    STUN_ATTRIBUTE_TYPE_FINGERPRINT         = 0x8028,
} StunAttributeType_t;
/*-----------------------------------------------------------*/

typedef struct StunContext
{
    const char * pStart;
    size_t totalLength;
    size_t currentIndex;
    uint32_t flags;
} StunContext_t;

typedef struct StunHeader
{
    StunMessageType_t messageType;
    uint8_t transactionId[ STUN_HEADER_TRANSACTION_ID_LENGTH ];
} StunHeader_t;

typedef struct StunAttribute
{
    StunAttributeType_t attributeType;
    const uint8_t * pAttributeValue;
    uint16_t attributeValueLength;
} StunAttribute_t;

typedef struct StunAttributeAddress
{
    uint8_t padding;
    uint8_t family;
    uint16_t port;
    uint8_t address[ 16 ];
} StunAttributeAddress_t;

/*-----------------------------------------------------------*/

#endif /* STUN_DATA_TYPES_H */
