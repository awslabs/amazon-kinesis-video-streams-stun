/* Standard includes. */
#include <stdio.h>
#include <string.h>

/* API includes. */
#include "stun_serializer.h"

/* Read/Write macros. */
#define STUN_WRITE_UINT16   ( pCtx->readWriteFunctions.writeUint16Fn )
#define STUN_WRITE_UINT32   ( pCtx->readWriteFunctions.writeUint32Fn )
#define STUN_WRITE_UINT64   ( pCtx->readWriteFunctions.writeUint64Fn )
#define STUN_READ_UINT16    ( pCtx->readWriteFunctions.readUint16Fn )
#define STUN_READ_UINT32    ( pCtx->readWriteFunctions.readUint32Fn )
#define STUN_READ_UINT64    ( pCtx->readWriteFunctions.readUint64Fn )

/*-----------------------------------------------------------*/

/* Static Functions. */
static StunResult_t CheckAndUpdateAttributeFlag( StunContext_t * pCtx,
                                                 StunAttributeType_t attributeType );

static StunResult_t XorAddress( StunContext_t * pCtx,
                                StunAttributeAddress_t * pAddress );

static StunResult_t AddAttributeTypeOnly( StunContext_t * pCtx,
                                          StunAttributeType_t attributeType );

static StunResult_t AddAttributeUint32( StunContext_t * pCtx,
                                        StunAttributeType_t attributeType,
                                        uint32_t attributeValue );

static StunResult_t AddAttributeUint64( StunContext_t * pCtx,
                                        StunAttributeType_t attributeType,
                                        uint64_t attributeValue );

static StunResult_t AddAttributeBuffer( StunContext_t * pCtx,
                                        StunAttributeType_t attributeType,
                                        const uint8_t * pAttributeValueBuffer,
                                        uint16_t attributeValueBufferLength );

/*-----------------------------------------------------------*/

static StunResult_t CheckAndUpdateAttributeFlag( StunContext_t * pCtx,
                                                 StunAttributeType_t attributeType )
{
    StunResult_t result = STUN_RESULT_OK;

    if( ( pCtx->attributeFlag & STUN_FLAG_FINGERPRINT_ATTRIBUTE ) != 0 )
    {
        /* No more attributes can be added after Fingerprint - it must  be
         * the last attribute. */
        result = STUN_RESULT_INVALID_ATTRIBUTE_ORDER;
    }
    else if( ( ( pCtx->attributeFlag & STUN_FLAG_INTEGRITY_ATTRIBUTE ) != 0 ) &&
             ( attributeType != STUN_ATTRIBUTE_TYPE_FINGERPRINT ) )
    {
        /* No attribute other than fingerprint can be added after Integrity
         * attribute. */
        result = STUN_RESULT_INVALID_ATTRIBUTE_ORDER;
    }

    if( result == STUN_RESULT_OK )
    {
        /* Update flags. */
        if( attributeType == STUN_ATTRIBUTE_TYPE_FINGERPRINT )
        {
            pCtx->attributeFlag |= STUN_FLAG_FINGERPRINT_ATTRIBUTE;
        }
        else if( attributeType == STUN_ATTRIBUTE_TYPE_MESSAGE_INTEGRITY )
        {
            pCtx->attributeFlag |= STUN_FLAG_INTEGRITY_ATTRIBUTE;
        }
    }

    return result;
}

/*-----------------------------------------------------------*/

static StunResult_t AddAttributeBuffer( StunContext_t * pCtx,
                                        StunAttributeType_t attributeType,
                                        const uint8_t * pAttributeValueBuffer,
                                        uint16_t attributeValueBufferLength )
{
    StunResult_t result = STUN_RESULT_OK;
    uint16_t attributeValueLengthPadded = STUN_ALIGN_SIZE_TO_WORD( attributeValueBufferLength );

    if( ( pCtx == NULL ) ||
        ( pAttributeValueBuffer == NULL ) ||
        ( attributeValueBufferLength == 0 ) )
    {
        result = STUN_RESULT_BAD_PARAM;
    }

    if( ( result == STUN_RESULT_OK ) &&
        ( pCtx->pStart != NULL ) )
    {
        if( STUN_REMAINING_LENGTH( pCtx ) < STUN_ATTRIBUTE_TOTAL_LENGTH( attributeValueLengthPadded ) )
        {
            result = STUN_RESULT_OUT_OF_MEMORY;
        }
    }

    if( result == STUN_RESULT_OK )
    {
        result = CheckAndUpdateAttributeFlag( pCtx,
                                              attributeType );
    }

    if( result == STUN_RESULT_OK )
    {
        if( pCtx->pStart != NULL )
        {
            /* Write Attribute type, length and value. */
            STUN_WRITE_UINT16( &( pCtx->pStart[ pCtx->currentIndex ] ),
                               attributeType );

            STUN_WRITE_UINT16( &( pCtx->pStart[ pCtx->currentIndex + STUN_ATTRIBUTE_HEADER_LENGTH_OFFSET ] ),
                               attributeValueBufferLength );

            memcpy( ( void * ) &( pCtx->pStart[ pCtx->currentIndex + STUN_ATTRIBUTE_HEADER_VALUE_OFFSET ] ),
                    ( const void * ) pAttributeValueBuffer,
                    attributeValueBufferLength );

            /* Zero out the padded bytes. */
            if( attributeValueLengthPadded > attributeValueBufferLength )
            {
                memset( ( void * ) &( pCtx->pStart[ pCtx->currentIndex +
                                                    STUN_ATTRIBUTE_TOTAL_LENGTH( attributeValueBufferLength ) ] ),
                        0,
                        attributeValueLengthPadded - attributeValueBufferLength );
            }
        }

        pCtx->currentIndex += STUN_ATTRIBUTE_TOTAL_LENGTH( attributeValueLengthPadded );
    }

    return result;
}

/*-----------------------------------------------------------*/

static StunResult_t AddAttributeTypeOnly( StunContext_t * pCtx,
                                          StunAttributeType_t attributeType )
{
    StunResult_t result = STUN_RESULT_OK;
    uint16_t attributeValueLength = 0;

    if( pCtx == NULL )
    {
        result = STUN_RESULT_BAD_PARAM;
    }

    if( ( result == STUN_RESULT_OK ) &&
        ( pCtx->pStart != NULL ) )
    {
        if( STUN_REMAINING_LENGTH( pCtx ) < STUN_ATTRIBUTE_TOTAL_LENGTH( attributeValueLength ) )
        {
            result = STUN_RESULT_OUT_OF_MEMORY;
        }
    }

    if( result == STUN_RESULT_OK )
    {
        result = CheckAndUpdateAttributeFlag( pCtx,
                                              attributeType );
    }

    if( result == STUN_RESULT_OK )
    {
        if( pCtx->pStart != NULL )
        {
            /* Write Attribute type, length and value. */
            STUN_WRITE_UINT16( &( pCtx->pStart[ pCtx->currentIndex ] ),
                               attributeType );

            STUN_WRITE_UINT16( &( pCtx->pStart[ pCtx->currentIndex + STUN_ATTRIBUTE_HEADER_LENGTH_OFFSET ] ),
                               attributeValueLength );
        }

        pCtx->currentIndex += STUN_ATTRIBUTE_TOTAL_LENGTH( attributeValueLength );
    }

    return result;
}

/*-----------------------------------------------------------*/

static StunResult_t AddAttributeUint32( StunContext_t * pCtx,
                                        StunAttributeType_t attributeType,
                                        uint32_t attributeValue )
{
    StunResult_t result = STUN_RESULT_OK;
    uint16_t attributeValueLength = sizeof( uint32_t );

    if( pCtx == NULL )
    {
        result = STUN_RESULT_BAD_PARAM;
    }

    if( ( result == STUN_RESULT_OK ) &&
        ( pCtx->pStart != NULL ) )
    {
        if( STUN_REMAINING_LENGTH( pCtx ) < STUN_ATTRIBUTE_TOTAL_LENGTH( attributeValueLength ) )
        {
            result = STUN_RESULT_OUT_OF_MEMORY;
        }
    }

    if( result == STUN_RESULT_OK )
    {
        result = CheckAndUpdateAttributeFlag( pCtx,
                                              attributeType );
    }

    if( result == STUN_RESULT_OK )
    {
        if( pCtx->pStart != NULL )
        {
            /* Write Attribute type, length and value. */
            STUN_WRITE_UINT16( &( pCtx->pStart[ pCtx->currentIndex ] ),
                               attributeType );

            STUN_WRITE_UINT16( &( pCtx->pStart[ pCtx->currentIndex + STUN_ATTRIBUTE_HEADER_LENGTH_OFFSET ] ),
                               attributeValueLength );

            STUN_WRITE_UINT32( &( pCtx->pStart[ pCtx->currentIndex + STUN_ATTRIBUTE_HEADER_VALUE_OFFSET ] ),
                               attributeValue );
        }

        pCtx->currentIndex += STUN_ATTRIBUTE_TOTAL_LENGTH( attributeValueLength );
    }

    return result;
}

/*-----------------------------------------------------------*/

static StunResult_t AddAttributeUint64( StunContext_t * pCtx,
                                        StunAttributeType_t attributeType,
                                        uint64_t attributeValue )
{
    StunResult_t result = STUN_RESULT_OK;
    uint16_t attributeValueLength = sizeof( uint64_t );

    if( pCtx == NULL )
    {
        result = STUN_RESULT_BAD_PARAM;
    }

    if( ( result == STUN_RESULT_OK ) &&
        ( pCtx->pStart != NULL ) )
    {
        if( STUN_REMAINING_LENGTH( pCtx ) < STUN_ATTRIBUTE_TOTAL_LENGTH( attributeValueLength ) )
        {
            result = STUN_RESULT_OUT_OF_MEMORY;
        }
    }

    if( result == STUN_RESULT_OK )
    {
        result = CheckAndUpdateAttributeFlag( pCtx,
                                              attributeType );
    }

    if( result == STUN_RESULT_OK )
    {
        if( pCtx->pStart != NULL )
        {
            /* Write Attribute type, length and value. */
            STUN_WRITE_UINT16( &( pCtx->pStart[ pCtx->currentIndex ] ),
                               attributeType );

            STUN_WRITE_UINT16( &( pCtx->pStart[ pCtx->currentIndex + STUN_ATTRIBUTE_HEADER_LENGTH_OFFSET ] ),
                               attributeValueLength );

            STUN_WRITE_UINT64( &( pCtx->pStart[ pCtx->currentIndex + STUN_ATTRIBUTE_HEADER_VALUE_OFFSET ] ),
                               attributeValue );
        }

        pCtx->currentIndex += STUN_ATTRIBUTE_TOTAL_LENGTH( attributeValueLength );
    }

    return result;
}

/*-----------------------------------------------------------*/

static StunResult_t XorAddress( StunContext_t * pCtx,
                                StunAttributeAddress_t * pAddress )
{
    StunResult_t result = STUN_RESULT_OK;
    uint16_t msbMagic = ( STUN_HEADER_MAGIC_COOKIE >> 16 );
    uint32_t word, xorWord, i;
    uint8_t byte, xorByte;

    if( pAddress == NULL ||
        ( ( pAddress->family != STUN_ADDRESS_IPv4 ) &&
          ( pAddress->family != STUN_ADDRESS_IPv6 ) ) )
    {
        result = STUN_RESULT_BAD_PARAM;
    }

    if( result == STUN_RESULT_OK )
    {
        pAddress->port = msbMagic ^ pAddress->port;

        word = STUN_READ_UINT32( &( pAddress->address[ 0 ] ) );
        xorWord = word ^ STUN_HEADER_MAGIC_COOKIE;
        STUN_WRITE_UINT32( &( pAddress->address[ 0 ] ), xorWord );

        if( pAddress->family == STUN_ADDRESS_IPv6 )
        {
            for( i = 0; i < STUN_HEADER_TRANSACTION_ID_LENGTH; i++ )
            {
                byte = pAddress->address[ STUN_IPV4_ADDRESS_SIZE + i ];
                xorByte = byte ^ pCtx->pStart[ STUN_HEADER_TRANSACTION_ID_OFFSET + i ];
                pAddress->address[ STUN_IPV4_ADDRESS_SIZE + i ] = xorByte;
            }
        }
    }

    return result;
}

/*-----------------------------------------------------------*/

StunResult_t StunSerializer_Init( StunContext_t * pCtx,
                                  uint8_t * pBuffer,
                                  size_t bufferLength,
                                  const StunHeader_t * pHeader )
{
    StunResult_t result = STUN_RESULT_OK;

    if( ( pCtx == NULL ) ||
        ( pHeader == NULL ) ||
        ( ( pBuffer != NULL ) &&
          ( bufferLength < STUN_HEADER_LENGTH ) ) )
    {
        result = STUN_RESULT_BAD_PARAM;
    }

    if( result == STUN_RESULT_OK )
    {
        Stun_InitReadWriteFunctions( &( pCtx->readWriteFunctions ) );

        pCtx->pStart = pBuffer;
        pCtx->totalLength = bufferLength;
        pCtx->currentIndex = 0;
        pCtx->attributeFlag = 0;

        if( pCtx->pStart != NULL )
        {
            STUN_WRITE_UINT16( &( pCtx->pStart[ pCtx->currentIndex ] ),
                               pHeader->messageType );

            /* Message length is updated in finalize. */
            STUN_WRITE_UINT16( &( pCtx->pStart[ pCtx->currentIndex + STUN_HEADER_MESSAGE_LENGTH_OFFSET ] ),
                               0 );

            STUN_WRITE_UINT32( &( pCtx->pStart[ pCtx->currentIndex + STUN_HEADER_MAGIC_COOKIE_OFFSET ] ),
                               STUN_HEADER_MAGIC_COOKIE );

            memcpy( ( void * ) &( pCtx->pStart[ pCtx->currentIndex + STUN_HEADER_TRANSACTION_ID_OFFSET ] ),
                    ( const void * ) &( pHeader->pTransactionId[ 0 ] ),
                    STUN_HEADER_TRANSACTION_ID_LENGTH );
        }

        pCtx->currentIndex += STUN_HEADER_LENGTH;
    }

    return result;
}

/*-----------------------------------------------------------*/

StunResult_t StunSerializer_AddAttributeErrorCode( StunContext_t * pCtx,
                                                   uint16_t errorCode,
                                                   const uint8_t * pErrorPhrase,
                                                   uint16_t errorPhraseLength )
{
    StunResult_t result = STUN_RESULT_OK;
    uint16_t attributeValueLength = STUN_ATTRIBUTE_ERROR_CODE_HEADER_LENGTH + errorPhraseLength;
    uint16_t attributeValueLengthPadded = STUN_ALIGN_SIZE_TO_WORD( attributeValueLength );
    uint16_t reserved = 0x0;

    if( pCtx == NULL ||
        ( pErrorPhrase == NULL ) ||
        ( errorPhraseLength == 0 ) )
    {
        result = STUN_RESULT_BAD_PARAM;
    }

    if( ( result == STUN_RESULT_OK ) &&
        ( pCtx->pStart != NULL ) )
    {
        if( STUN_REMAINING_LENGTH( pCtx ) < STUN_ATTRIBUTE_TOTAL_LENGTH( attributeValueLengthPadded ) )
        {
            result = STUN_RESULT_OUT_OF_MEMORY;
        }
    }

    if( result == STUN_RESULT_OK )
    {
        result = CheckAndUpdateAttributeFlag( pCtx,
                                              STUN_ATTRIBUTE_TYPE_ERROR_CODE );
    }

    if( result == STUN_RESULT_OK )
    {
        if( pCtx->pStart != NULL )
        {
            /* Write Attribute type, length and value. */
            STUN_WRITE_UINT16( &( pCtx->pStart[ pCtx->currentIndex ] ),
                               STUN_ATTRIBUTE_TYPE_ERROR_CODE );

            STUN_WRITE_UINT16( &( pCtx->pStart[ pCtx->currentIndex + STUN_ATTRIBUTE_HEADER_LENGTH_OFFSET ] ),
                               attributeValueLength );

            /* Set reserved bits to zero. */
            STUN_WRITE_UINT16( &( pCtx->pStart[ pCtx->currentIndex + STUN_ATTRIBUTE_HEADER_VALUE_OFFSET ] ),
                               reserved );

            STUN_WRITE_UINT16( &( pCtx->pStart[ pCtx->currentIndex +
                                                STUN_ATTRIBUTE_HEADER_VALUE_OFFSET +
                                                STUN_ATTRIBUTE_ERROR_CODE_CLASS_OFFSET ] ),
                               errorCode );

            memcpy( ( void * ) &( pCtx->pStart[ pCtx->currentIndex +
                                                STUN_ATTRIBUTE_HEADER_VALUE_OFFSET +
                                                STUN_ATTRIBUTE_ERROR_CODE_REASON_PHRASE_OFFSET ] ),
                    ( const void * ) pErrorPhrase,
                    errorPhraseLength );

            /* Zero out the padded bytes. */
            if( attributeValueLengthPadded > attributeValueLength )
            {
                memset( ( void * ) &( pCtx->pStart[ pCtx->currentIndex +
                                                    STUN_ATTRIBUTE_TOTAL_LENGTH( attributeValueLength ) ] ),
                        0,
                        attributeValueLengthPadded - attributeValueLength );
            }
        }

        pCtx->currentIndex += STUN_ATTRIBUTE_TOTAL_LENGTH( attributeValueLengthPadded );
    }

    return result;
}

/*-----------------------------------------------------------*/

StunResult_t StunSerializer_AddAttributeChannelNumber( StunContext_t * pCtx,
                                                       uint16_t channelNumber )
{
    StunResult_t result = STUN_RESULT_OK;
    uint16_t attributeValueLength = STUN_ATTRIBUTE_CHANNEL_NUMBER_LENGTH;
    uint16_t reserved = 0;

    if( pCtx == NULL )
    {
        result = STUN_RESULT_BAD_PARAM;
    }

    if( ( result == STUN_RESULT_OK ) &&
        ( pCtx->pStart != NULL ) )
    {
        if( STUN_REMAINING_LENGTH( pCtx ) < STUN_ATTRIBUTE_TOTAL_LENGTH( attributeValueLength ) )
        {
            result = STUN_RESULT_OUT_OF_MEMORY;
        }
    }

    if( result == STUN_RESULT_OK )
    {
        result = CheckAndUpdateAttributeFlag( pCtx,
                                              STUN_ATTRIBUTE_TYPE_ERROR_CODE );
    }

    if( result == STUN_RESULT_OK )
    {
        if( pCtx->pStart != NULL )
        {
            /* Write Attribute type, length and value. */
            STUN_WRITE_UINT16( &( pCtx->pStart[ pCtx->currentIndex ] ),
                               STUN_ATTRIBUTE_TYPE_CHANNEL_NUMBER );

            STUN_WRITE_UINT16( &( pCtx->pStart[ pCtx->currentIndex + STUN_ATTRIBUTE_HEADER_LENGTH_OFFSET ] ),
                               attributeValueLength );

            STUN_WRITE_UINT16( &( pCtx->pStart[ pCtx->currentIndex +
                                                STUN_ATTRIBUTE_HEADER_VALUE_OFFSET +
                                                STUN_ATTRIBUTE_CHANNEL_NUMBER_OFFSET ] ),
                               channelNumber );

            STUN_WRITE_UINT16( &( pCtx->pStart[ pCtx->currentIndex +
                                                STUN_ATTRIBUTE_HEADER_VALUE_OFFSET +
                                                STUN_ATTRIBUTE_CHANNEL_NUMBER_RESERVED_OFFSET ] ),
                               reserved );
        }

        pCtx->currentIndex += STUN_ATTRIBUTE_TOTAL_LENGTH( attributeValueLength );
    }

    return result;
}

/*-----------------------------------------------------------*/

StunResult_t StunSerializer_AddAttributeUseCandidate( StunContext_t * pCtx )
{
    return AddAttributeTypeOnly( pCtx,
                                 STUN_ATTRIBUTE_TYPE_USE_CANDIDATE );
}

/*-----------------------------------------------------------*/

StunResult_t StunSerializer_AddAttributeDontFragment( StunContext_t * pCtx )
{
    return AddAttributeTypeOnly( pCtx,
                                 STUN_ATTRIBUTE_TYPE_DONT_FRAGMENT );
}

/*-----------------------------------------------------------*/

StunResult_t StunSerializer_AddAttributePriority( StunContext_t * pCtx,
                                                  uint32_t priority )
{
    return AddAttributeUint32( pCtx,
                               STUN_ATTRIBUTE_TYPE_PRIORITY,
                               priority );
}

/*-----------------------------------------------------------*/

StunResult_t StunSerializer_AddAttributeFingerprint( StunContext_t * pCtx,
                                                     uint32_t crc32Fingerprint )
{
    return AddAttributeUint32( pCtx,
                               STUN_ATTRIBUTE_TYPE_FINGERPRINT,
                               crc32Fingerprint );
}

/*-----------------------------------------------------------*/

StunResult_t StunSerializer_AddAttributeLifetime( StunContext_t * pCtx,
                                                  uint32_t lifetime )
{
    return AddAttributeUint32( pCtx,
                               STUN_ATTRIBUTE_TYPE_LIFETIME,
                               lifetime );
}

/*-----------------------------------------------------------*/

StunResult_t StunSerializer_AddAttributeChangeRequest( StunContext_t * pCtx,
                                                       uint32_t changeFlag )
{
    return AddAttributeUint32( pCtx,
                               STUN_ATTRIBUTE_TYPE_CHANGE_REQUEST,
                               changeFlag );
}

/*-----------------------------------------------------------*/

StunResult_t StunSerializer_AddAttributeIceControlled( StunContext_t * pCtx,
                                                       uint64_t tieBreaker )
{
    return AddAttributeUint64( pCtx,
                               STUN_ATTRIBUTE_TYPE_ICE_CONTROLLED,
                               tieBreaker );
}

/*-----------------------------------------------------------*/

StunResult_t StunSerializer_AddAttributeIceControlling( StunContext_t * pCtx,
                                                        uint64_t tieBreaker )
{
    return AddAttributeUint64( pCtx,
                               STUN_ATTRIBUTE_TYPE_ICE_CONTROLLING,
                               tieBreaker );
}

/*-----------------------------------------------------------*/

StunResult_t StunSerializer_AddAttributeUsername( StunContext_t * pCtx,
                                                  const uint8_t * pUsername,
                                                  uint16_t usernameLength )
{
    return AddAttributeBuffer( pCtx,
                               STUN_ATTRIBUTE_TYPE_USERNAME,
                               pUsername,
                               usernameLength );
}

/*-----------------------------------------------------------*/

StunResult_t StunSerializer_AddAttributeData( StunContext_t * pCtx,
                                              const uint8_t * pData,
                                              uint16_t dataLength )
{
    return AddAttributeBuffer( pCtx,
                               STUN_ATTRIBUTE_TYPE_DATA,
                               pData,
                               dataLength );
}

/*-----------------------------------------------------------*/

StunResult_t StunSerializer_AddAttributeRealm( StunContext_t * pCtx,
                                               const uint8_t * pRealm,
                                               uint16_t realmLength )
{
    return AddAttributeBuffer( pCtx,
                               STUN_ATTRIBUTE_TYPE_REALM,
                               pRealm,
                               realmLength );
}

/*-----------------------------------------------------------*/

StunResult_t StunSerializer_AddAttributeNonce( StunContext_t * pCtx,
                                               const uint8_t * pNonce,
                                               uint16_t nonceLength )
{
    return AddAttributeBuffer( pCtx,
                               STUN_ATTRIBUTE_TYPE_NONCE,
                               pNonce,
                               nonceLength );
}

/*-----------------------------------------------------------*/

StunResult_t StunSerializer_AddAttributeRequestedTransport( StunContext_t * pCtx,
                                                            const uint8_t * pRequestedTransport,
                                                            uint16_t requestedTransportLength )
{
    return AddAttributeBuffer( pCtx,
                               STUN_ATTRIBUTE_TYPE_REQUESTED_TRANSPORT,
                               pRequestedTransport,
                               requestedTransportLength );
}

/*-----------------------------------------------------------*/

StunResult_t StunSerializer_AddAttributeIntegrity( StunContext_t * pCtx,
                                                   const uint8_t * pIntegrity,
                                                   uint16_t integrityLength )
{
    return AddAttributeBuffer( pCtx,
                               STUN_ATTRIBUTE_TYPE_MESSAGE_INTEGRITY,
                               pIntegrity,
                               integrityLength );
}

/*-----------------------------------------------------------*/

StunResult_t StunSerializer_AddAttributeAddress( StunContext_t * pCtx,
                                                 StunAttributeAddress_t * pAddress,
                                                 StunAttributeType_t attributeType )
{
    StunResult_t result = STUN_RESULT_OK;
    uint16_t attributeValueLength = 0;
    size_t addressLength;

    if( pAddress == NULL ||
        ( ( pAddress->family != STUN_ADDRESS_IPv4 ) &&
          ( pAddress->family != STUN_ADDRESS_IPv6 ) ) )
    {
        result = STUN_RESULT_BAD_PARAM;
    }

    if( ( result == STUN_RESULT_OK ) &&
        ( pCtx->pStart != NULL ) )
    {
        if( STUN_REMAINING_LENGTH( pCtx ) < STUN_ATTRIBUTE_TOTAL_LENGTH( attributeValueLength ) )
        {
            result = STUN_RESULT_OUT_OF_MEMORY;
        }
    }

    if( result == STUN_RESULT_OK )
    {
        attributeValueLength = STUN_ATTRIBUTE_ADDRESS_HEADER_LENGTH +
                               ( ( pAddress->family == STUN_ADDRESS_IPv4 ) ? STUN_IPV4_ADDRESS_SIZE :
                                                                             STUN_IPV6_ADDRESS_SIZE );

        result = CheckAndUpdateAttributeFlag( pCtx,
                                              attributeType );
    }

    if( ( result == STUN_RESULT_OK ) &&
        ( pCtx->pStart != NULL ) &&
        ( ( attributeType == STUN_ATTRIBUTE_TYPE_XOR_MAPPED_ADDRESS ) ||
          ( attributeType == STUN_ATTRIBUTE_TYPE_XOR_RELAYED_ADDRESS ) ||
          ( attributeType == STUN_ATTRIBUTE_TYPE_XOR_PEER_ADDRESS ) ) )
    {
        XorAddress( pCtx, pAddress );
    }

    if( result == STUN_RESULT_OK )
    {
        if( pCtx->pStart != NULL )
        {
            /* Write Attribute type, length and value. */
            STUN_WRITE_UINT16( &( pCtx->pStart[ pCtx->currentIndex ] ),
                               attributeType );

            STUN_WRITE_UINT16( &( pCtx->pStart[ pCtx->currentIndex + STUN_ATTRIBUTE_HEADER_LENGTH_OFFSET ] ),
                               attributeValueLength );

            STUN_WRITE_UINT16( &( pCtx->pStart[ pCtx->currentIndex +
                                                STUN_ATTRIBUTE_HEADER_VALUE_OFFSET +
                                                STUN_ATTRIBUTE_ADDRESS_FAMILY_OFFSET ] ),
                               pAddress->family );

            STUN_WRITE_UINT16( &( pCtx->pStart[ pCtx->currentIndex +
                                                STUN_ATTRIBUTE_HEADER_VALUE_OFFSET +
                                                STUN_ATTRIBUTE_ADDRESS_PORT_OFFSET ] ),
                               pAddress->port );

            addressLength = ( pAddress->family == STUN_ADDRESS_IPv4 ) ? STUN_IPV4_ADDRESS_SIZE:
                                                                        STUN_IPV6_ADDRESS_SIZE;
            memcpy( ( void * ) &( pCtx->pStart[ pCtx->currentIndex +
                                                STUN_ATTRIBUTE_HEADER_VALUE_OFFSET +
                                                STUN_ATTRIBUTE_ADDRESS_IP_ADDRESS_OFFSET ] ),
                    ( const void * ) &( pAddress->address[ 0 ] ),
                    addressLength );
        }

        pCtx->currentIndex += STUN_ATTRIBUTE_TOTAL_LENGTH( attributeValueLength );
    }

    return result;
}

/*-----------------------------------------------------------*/

StunResult_t StunSerializer_AddAttributeMappedAddress( StunContext_t * pCtx,
                                                       StunAttributeAddress_t * pMappedAddress )
{
    return StunSerializer_AddAttributeAddress( pCtx,
                                               pMappedAddress,
                                               STUN_ATTRIBUTE_TYPE_MAPPED_ADDRESS );
}

/*-----------------------------------------------------------*/

StunResult_t StunSerializer_AddAttributeResponseAddress( StunContext_t * pCtx,
                                                         StunAttributeAddress_t * pResponseAddress )
{
    return StunSerializer_AddAttributeAddress( pCtx,
                                               pResponseAddress,
                                               STUN_ATTRIBUTE_TYPE_RESPONSE_ADDRESS );
}

/*-----------------------------------------------------------*/

StunResult_t StunSerializer_AddAttributeSourceAddress( StunContext_t * pCtx,
                                                       StunAttributeAddress_t * pSourceAddress )
{
    return StunSerializer_AddAttributeAddress( pCtx,
                                               pSourceAddress,
                                               STUN_ATTRIBUTE_TYPE_SOURCE_ADDRESS );
}

/*-----------------------------------------------------------*/

StunResult_t StunSerializer_AddAttributeChangedAddress( StunContext_t * pCtx,
                                                        StunAttributeAddress_t * pChangedAddress )
{
    return StunSerializer_AddAttributeAddress( pCtx,
                                               pChangedAddress,
                                               STUN_ATTRIBUTE_TYPE_CHANGED_ADDRESS );
}

/*-----------------------------------------------------------*/

StunResult_t StunSerializer_AddAttributeChangedReflectedFrom( StunContext_t * pCtx,
                                                              StunAttributeAddress_t * pReflectedFromAddress )
{
    return StunSerializer_AddAttributeAddress( pCtx,
                                               pReflectedFromAddress,
                                               STUN_ATTRIBUTE_TYPE_REFLECTED_FROM );
}

/*-----------------------------------------------------------*/

StunResult_t StunSerializer_AddAttributeXorMappedAddress( StunContext_t * pCtx,
                                                          StunAttributeAddress_t * pMappedAddress )
{
    return StunSerializer_AddAttributeAddress( pCtx,
                                               pMappedAddress,
                                               STUN_ATTRIBUTE_TYPE_XOR_MAPPED_ADDRESS );
}

/*-----------------------------------------------------------*/

StunResult_t StunSerializer_AddAttributeXorPeerAddress( StunContext_t * pCtx,
                                                        StunAttributeAddress_t * pPeerAddress )
{
    return StunSerializer_AddAttributeAddress( pCtx,
                                               pPeerAddress,
                                               STUN_ATTRIBUTE_TYPE_XOR_PEER_ADDRESS );
}

/*-----------------------------------------------------------*/

StunResult_t StunSerializer_AddAttributeXorRelayedAddress( StunContext_t * pCtx,
                                                           StunAttributeAddress_t * pRelayedAddress )
{
    return StunSerializer_AddAttributeAddress( pCtx,
                                               pRelayedAddress,
                                               STUN_ATTRIBUTE_TYPE_XOR_RELAYED_ADDRESS );
}

/*-----------------------------------------------------------*/

StunResult_t StunSerializer_GetIntegrityBuffer( StunContext_t * pCtx,
                                                uint8_t ** ppStunMessage,
                                                uint16_t * pStunMessageLength )
{
    StunResult_t result = STUN_RESULT_OK;

    if( ( pCtx == NULL ) ||
        ( pStunMessageLength == NULL ) )
    {
        result = STUN_RESULT_BAD_PARAM;
    }

    if( result == STUN_RESULT_OK )
    {
        if( pCtx->pStart != NULL )
        {
            /* Fix-up the packet length with message integrity and without the
             * STUN header. */
            STUN_WRITE_UINT16( &( pCtx->pStart[ STUN_HEADER_MESSAGE_LENGTH_OFFSET ] ),
                               pCtx->currentIndex -
                               STUN_HEADER_LENGTH +
                               STUN_ATTRIBUTE_TOTAL_LENGTH( STUN_HMAC_VALUE_LENGTH ) );

            *ppStunMessage =  ( uint8_t * )( pCtx->pStart );
        }

        *pStunMessageLength = pCtx->currentIndex;
    }

    return result;
}

/*-----------------------------------------------------------*/

StunResult_t StunSerializer_GetFingerprintBuffer( StunContext_t * pCtx,
                                                  uint8_t ** ppStunMessage,
                                                  uint16_t * pStunMessageLength )
{
    StunResult_t result = STUN_RESULT_OK;

    if( ( pCtx == NULL ) ||
        ( pStunMessageLength == NULL ) )
    {
        result = STUN_RESULT_BAD_PARAM;
    }

    if( result == STUN_RESULT_OK )
    {
        if( pCtx->pStart != NULL )
        {
            /* Fix-up the packet length with fingerprint CRC and without the
             * STUN header. */
            STUN_WRITE_UINT16( &( pCtx->pStart[ STUN_HEADER_MESSAGE_LENGTH_OFFSET ] ),
                               pCtx->currentIndex -
                               STUN_HEADER_LENGTH +
                               STUN_ATTRIBUTE_TOTAL_LENGTH( STUN_ATTRIBUTE_FINGERPRINT_LENGTH ) );

            *ppStunMessage =  ( uint8_t * )( pCtx->pStart );
        }

        *pStunMessageLength = pCtx->currentIndex;
    }

    return result;
}

/*-----------------------------------------------------------*/

StunResult_t StunSerializer_Finalize( StunContext_t * pCtx,
                                      uint32_t * pStunMessageLength )
{
    StunResult_t result = STUN_RESULT_OK;

    if( ( pCtx == NULL ) ||
        ( pStunMessageLength == NULL ) )
    {
        result = STUN_RESULT_BAD_PARAM;
    }

    if( result == STUN_RESULT_OK )
    {
        if( pCtx->pStart != NULL )
        {
            /* Update the message length field in the header. */
            STUN_WRITE_UINT16( &( pCtx->pStart[ STUN_HEADER_MESSAGE_LENGTH_OFFSET ] ),
                               pCtx->currentIndex - STUN_HEADER_LENGTH );
        }

        *pStunMessageLength = pCtx->currentIndex;
    }

    return result;
}

/*-----------------------------------------------------------*/
