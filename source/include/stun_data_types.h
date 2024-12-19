#ifndef STUN_DATA_TYPES_H
#define STUN_DATA_TYPES_H

/* Standard includes. */
#include <stdint.h>
#include <stddef.h>

/* Endianness includes. */
#include "stun_endianness.h"

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
#define STUN_ATTRIBUTE_HEADER_LENGTH                    4
#define STUN_ATTRIBUTE_HEADER_LENGTH_OFFSET             2
#define STUN_ATTRIBUTE_HEADER_VALUE_OFFSET              4
/*
 * STUN Channel-Number Attribute:
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |        Channel Number         |         RFFU = 0              |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * RFFU = Reserved For Future Use.
 */
#define STUN_ATTRIBUTE_CHANNEL_NUMBER_VALUE_LENGTH      4
#define STUN_ATTRIBUTE_CHANNEL_NUMBER_OFFSET            0
#define STUN_ATTRIBUTE_CHANNEL_NUMBER_RESERVED_OFFSET   2

/* Message Integrity attribute contains an HMAC-SHA1 that has a fixed length of
 * 20 bytes. */
#define STUN_ATTRIBUTE_INTEGRITY_VALUE_LENGTH           20

/* Fingerprint attribute. */
#define STUN_ATTRIBUTE_FINGERPRINT_VALUE_LENGTH         4
#define STUN_ATTRIBUTE_FINGERPRINT_XOR_VALUE            0x5354554E

/*
 * STUN Address Attribute:
 *
 * 0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |0 0 0 0 0 0 0 0|    Family     |         X-Port                |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                X-Address (Variable)
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
#define STUN_ATTRIBUTE_ADDRESS_FAMILY_OFFSET            0
#define STUN_ATTRIBUTE_ADDRESS_PORT_OFFSET              2
#define STUN_ATTRIBUTE_ADDRESS_HEADER_LENGTH            4
#define STUN_ATTRIBUTE_ADDRESS_IP_ADDRESS_OFFSET        4
#define STUN_ATTRIBUTE_ADDRESS_IPV4_VALUE_LENGTH        8
#define STUN_ATTRIBUTE_ADDRESS_IPV6_VALUE_LENGTH        20

/*
 * STUN Error-Code Attribute:
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           Reserved, should be 0         |Class|     Number    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |      Reason Phrase (variable)                                ..
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
#define STUN_ATTRIBUTE_ERROR_CODE_CLASS_OFFSET          2
#define STUN_ATTRIBUTE_ERROR_CODE_NUMBER_OFFSET         3
#define STUN_ATTRIBUTE_ERROR_CODE_HEADER_LENGTH         4
#define STUN_ATTRIBUTE_ERROR_CODE_REASON_PHRASE_OFFSET  4
#define STUN_ATTRIBUTE_ERROR_CODE_VALUE_MIN_LENGTH      4 /* No reason phrase. */
#define STUN_ATTRIBUTE_ERROR_CODE_VALUE_MAX_LENGTH      512

/* Attribute value lengths. */
#define STUN_ATTRIBUTE_PRIORITY_VALUE_LENGTH            4 /* 32-bit priority value. */
#define STUN_ATTRIBUTE_LIFETIME_VALUE_LENGTH            4 /* 32-bit lifetime value. */
#define STUN_ATTRIBUTE_CHANGE_REQUEST_VALUE_LENGTH      4 /* 32-bit flag. */
#define STUN_ATTRIBUTE_DONT_FRAGMENT_VALUE_LENGTH       0 /* Type only attribute. */
#define STUN_ATTRIBUTE_USE_CANDIDATE_VALUE_LENGTH       0 /* Type only attribute. */
#define STUN_ATTRIBUTE_ICE_CONTROLLED_VALUE_LENGTH      8 /* 64-bit tie breaker value. */
#define STUN_ATTRIBUTE_ICE_CONTROLLING_VALUE_LENGTH     8 /* 64-bit tie breaker value. */

/* Helper macros. */
#define STUN_ALIGN_SIZE_TO_WORD( size )                 ( ( ( size ) + 0x3 ) & ~( 0x3 ) )
#define STUN_REMAINING_LENGTH( pCtx )                   ( ( pCtx )->totalLength - ( pCtx )->currentIndex )
#define STUN_ATTRIBUTE_TOTAL_LENGTH( valueLength )      ( valueLength + STUN_ATTRIBUTE_HEADER_LENGTH )
#define STUN_GET_ERROR( class, number )                 ( ( uint16_t ) ( ( ( uint8_t ) ( class ) ) * 100 + ( uint8_t ) ( number ) ) )
#define STUN_GET_ERROR_CLASS( errorCode )               ( ( uint8_t ) ( ( errorCode ) / 100 ) )
#define STUN_GET_ERROR_NUMBER( errorCode )              ( ( uint8_t ) ( ( errorCode ) % 100 ) )

/* IP address macros. */
#define STUN_ADDRESS_IPv4           0x01
#define STUN_ADDRESS_IPv6           0x02

#define STUN_IPV4_ADDRESS_SIZE      0x04
#define STUN_IPV6_ADDRESS_SIZE      0x10

/* STUN context flags. */
#define STUN_FLAG_FINGERPRINT_ATTRIBUTE             ( 1 << 0 )
#define STUN_FLAG_INTEGRITY_ATTRIBUTE               ( 1 << 1 )

/*-----------------------------------------------------------*/

/* Return value from APIs. */
typedef enum StunResult
{
    STUN_RESULT_OK,
    STUN_RESULT_BASE,
    STUN_RESULT_BAD_PARAM,
    STUN_RESULT_OUT_OF_MEMORY,
    STUN_RESULT_INVALID_MESSAGE_LENGTH,
    STUN_RESULT_MAGIC_COOKIE_MISMATCH,
    STUN_RESULT_NO_MORE_ATTRIBUTE_FOUND,
    STUN_RESULT_INVALID_ATTRIBUTE_LENGTH,
    STUN_RESULT_INVALID_ATTRIBUTE_ORDER,
    STUN_RESULT_NO_ATTRIBUTE_FOUND,
    STUN_RESULT_INVALID_ATTRIBUTE,
} StunResult_t;

/* STUN message types. */
typedef enum StunMessageType
{
    STUN_MESSAGE_TYPE_BINDING_REQUEST = 0x0001,
    STUN_MESSAGE_TYPE_BINDING_SUCCESS_RESPONSE = 0x0101,
    STUN_MESSAGE_TYPE_BINDING_FAILURE_RESPONSE = 0x0111,
    STUN_MESSAGE_TYPE_BINDING_INDICATION = 0x0011,
    STUN_MESSAGE_TYPE_ALLOCATE_REQUEST = 0x0003,
    STUN_MESSAGE_TYPE_ALLOCATE_SUCCESS_RESPONSE = 0x0103,
    STUN_MESSAGE_TYPE_ALLOCATE_ERROR_RESPONSE = 0x0113,
    STUN_MESSAGE_TYPE_REFRESH_REQUEST = 0x0004,
    STUN_MESSAGE_TYPE_REFRESH_SUCCESS_RESPONSE = 0x0104,
    STUN_MESSAGE_TYPE_REFRESH_ERROR_RESPONSE = 0x0114,
    STUN_MESSAGE_TYPE_CREATE_PERMISSION_REQUEST = 0x0008,
    STUN_MESSAGE_TYPE_CREATE_PERMISSION_SUCCESS_RESPONSE = 0x0108,
    STUN_MESSAGE_TYPE_CREATE_PERMISSION_ERROR_RESPONSE = 0x0118,
    STUN_MESSAGE_TYPE_CHANNEL_BIND_REQUEST = 0x0009,
    STUN_MESSAGE_TYPE_CHANNEL_BIND_SUCCESS_RESPONSE = 0x0109,
    STUN_MESSAGE_TYPE_CHANNEL_BIND_ERROR_RESPONSE = 0x0119,
    STUN_MESSAGE_TYPE_SEND_INDICATION = 0x0016,
    STUN_MESSAGE_TYPE_DATA_INDICATION = 0x0017,
} StunMessageType_t;

/* STUN attribute types. */
typedef enum StunAttributeType
{
    STUN_ATTRIBUTE_TYPE_MAPPED_ADDRESS = 0x0001,
    STUN_ATTRIBUTE_TYPE_RESPONSE_ADDRESS = 0x0002,
    STUN_ATTRIBUTE_TYPE_CHANGE_REQUEST = 0x0003,
    STUN_ATTRIBUTE_TYPE_SOURCE_ADDRESS = 0x0004,
    STUN_ATTRIBUTE_TYPE_CHANGED_ADDRESS = 0x0005,
    STUN_ATTRIBUTE_TYPE_USERNAME = 0x0006,
    STUN_ATTRIBUTE_TYPE_PASSWORD = 0x0007,
    STUN_ATTRIBUTE_TYPE_MESSAGE_INTEGRITY = 0x0008,
    STUN_ATTRIBUTE_TYPE_ERROR_CODE = 0x0009,
    STUN_ATTRIBUTE_TYPE_UNKNOWN_ATTRIBUTES = 0x000A,
    STUN_ATTRIBUTE_TYPE_REFLECTED_FROM = 0x000B,
    STUN_ATTRIBUTE_TYPE_CHANNEL_NUMBER = 0x000C,
    STUN_ATTRIBUTE_TYPE_LIFETIME = 0x000D,
    STUN_ATTRIBUTE_TYPE_XOR_PEER_ADDRESS = 0x0012,
    STUN_ATTRIBUTE_TYPE_DATA = 0x0013,
    STUN_ATTRIBUTE_TYPE_REALM = 0x0014,
    STUN_ATTRIBUTE_TYPE_NONCE = 0x0015,
    STUN_ATTRIBUTE_TYPE_XOR_RELAYED_ADDRESS = 0x0016,
    STUN_ATTRIBUTE_TYPE_EVEN_PORT = 0x0018,
    STUN_ATTRIBUTE_TYPE_REQUESTED_TRANSPORT = 0x0019,
    STUN_ATTRIBUTE_TYPE_DONT_FRAGMENT = 0x001A,
    STUN_ATTRIBUTE_TYPE_XOR_MAPPED_ADDRESS = 0x0020,
    STUN_ATTRIBUTE_TYPE_RESERVATION_TOKEN = 0x0022,
    STUN_ATTRIBUTE_TYPE_PRIORITY = 0x0024,
    STUN_ATTRIBUTE_TYPE_USE_CANDIDATE = 0x0025,
    STUN_ATTRIBUTE_TYPE_FINGERPRINT = 0x8028,
    STUN_ATTRIBUTE_TYPE_ICE_CONTROLLED = 0x8029,
    STUN_ATTRIBUTE_TYPE_ICE_CONTROLLING = 0x802A,
} StunAttributeType_t;

/**
 * Requested Transport protocol value (IP header protocol field).
 * As per RFC 8656 and IP protocol numbers list:
 * - https://datatracker.ietf.org/doc/html/rfc8656#name-requested-transport
 * - https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
 */
typedef enum StunAttributeRequestedTransport
{
    STUN_ATTRIBUTE_REQUESTED_TRANSPORT_NONE = 0,
    STUN_ATTRIBUTE_REQUESTED_TRANSPORT_UDP = 17,
} StunAttributeRequestedTransport_t;

/**
 * STUN error codes
 */
typedef enum StunAttributeErrorCode {
    STUN_ATTRIBUTE_ERROR_CODE_SUCCESS = 0,
    STUN_ATTRIBUTE_ERROR_CODE_UNAUTHORIZED = 401,
    STUN_ATTRIBUTE_ERROR_CODE_STALE_NONCE = 438,
} StunAttributeErrorCode_t;

/*-----------------------------------------------------------*/

typedef struct StunContext
{
    uint8_t * pStart;
    size_t totalLength;
    size_t currentIndex;
    uint32_t attributeFlag;
    StunReadWriteFunctions_t readWriteFunctions;
} StunContext_t;

/* This cannot be struct StunHeader to avoid collision with the same name in
 * the KVS WebRTC C-SDK. */
typedef struct StunMessageHeader
{
    StunMessageType_t messageType;
    uint8_t * pTransactionId;
} StunHeader_t;

typedef struct StunAttribute
{
    StunAttributeType_t attributeType;
    uint8_t * pAttributeValue;
    uint16_t attributeValueLength;
} StunAttribute_t;

/* This cannot be struct StunAttributeAddress to avoid collision with the same
 * name in the KVS WebRTC C-SDK. */
typedef struct StunAttributesAddress
{
    uint16_t family;
    uint16_t port;
    uint8_t address[ STUN_IPV6_ADDRESS_SIZE ];
} StunAttributeAddress_t;

/*-----------------------------------------------------------*/

#endif /* STUN_DATA_TYPES_H */
