/* Standard includes. */
#include <stdio.h>
#include <string.h>

/* API includes. */
#include "stun_serializer.h"

/* Read/Write flags. */
#define STUN_WRITE_UINT16   ( pCtx->readWriteFn.WriteU16Fn )
#define STUN_WRITE_UINT32   ( pCtx->readWriteFn.WriteU32Fn )
#define STUN_WRITE_UINT64   ( pCtx->readWriteFn.WriteU64Fn )
#define STUN_READ_UINT16    ( pCtx->readWriteFn.ReadU16Fn )
#define STUN_READ_UINT32    ( pCtx->readWriteFn.ReadU32Fn )
#define STUN_READ_UINT64    ( pCtx->readWriteFn.ReadU64Fn )

static StunResult_t AddAttributeBuffer( StunContext_t * pCtx,
                                        StunAttributeType_t attributeType,
                                        const uint8_t * pAttributeValueBuffer,
                                        uint16_t attributeValueBufferLength );

static StunResult_t AddAttributeFlag( StunContext_t * pCtx,
                                      StunAttributeType_t attributeType );

static StunResult_t AddAttributeU32( StunContext_t * pCtx,
                                     StunAttributeType_t attributeType,
                                     uint32_t attributeValue );

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
    }

    if( result == STUN_RESULT_OK )
    {
        /* Update flags. */
        if( attributeType == STUN_ATTRIBUTE_TYPE_FINGERPRINT )
        {
            pCtx->attributeFlag |= STUN_FLAG_FINGERPRINT_ATTRIBUTE;
        }
        if( attributeType == STUN_ATTRIBUTE_TYPE_MESSAGE_INTEGRITY )
        {
            pCtx->attributeFlag |= STUN_FLAG_INTEGRITY_ATTRIBUTE;
        }

        if( pCtx->pStart != NULL )
        {
            /* Write Attribute type, length and value. */
            STUN_WRITE_UINT16( (uint8_t *) &( pCtx->pStart[ pCtx->currentIndex ] ),
                                attributeType );

            STUN_WRITE_UINT16( (uint8_t *) &( pCtx->pStart[ pCtx->currentIndex + STUN_ATTRIBUTE_HEADER_LENGTH_OFFSET ] ),
                                attributeValueBufferLength );

            memcpy( ( void * ) &( pCtx->pStart[ pCtx->currentIndex + STUN_ATTRIBUTE_HEADER_VALUE_OFFSET ] ),
                    pAttributeValueBuffer,
                    attributeValueBufferLength );

            /* Zero out the padded bytes. */
            if( attributeValueLengthPadded > attributeValueBufferLength )
            {
                memset( ( void * ) &( pCtx->pStart[ pCtx->currentIndex + STUN_ATTRIBUTE_TOTAL_LENGTH( attributeValueBufferLength ) ] ),
                        0,
                        attributeValueLengthPadded - attributeValueBufferLength );
            }
        }

        pCtx->currentIndex += STUN_ATTRIBUTE_TOTAL_LENGTH( attributeValueLengthPadded );
    }

    return result;
}
/*-----------------------------------------------------------*/

static StunResult_t AddAttributeFlag( StunContext_t * pCtx,
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
        if( ( pCtx->attributeFlag & STUN_FLAG_FINGERPRINT_ATTRIBUTE ) != 0 ||
            ( pCtx->attributeFlag & STUN_FLAG_INTEGRITY_ATTRIBUTE ) != 0 )
        {
            /* No more attributes can be added after Fingerprint & Integrity. */
            result = STUN_RESULT_INVALID_ATTRIBUTE_ORDER;
        }
    }

    if( result == STUN_RESULT_OK )
    {
        if( pCtx->pStart != NULL )
        {
            /* Write Attribute type, length and value. */
            STUN_WRITE_UINT16( (uint8_t *) &( pCtx->pStart[ pCtx->currentIndex ] ),
                                attributeType );

            STUN_WRITE_UINT16( (uint8_t *) &( pCtx->pStart[ pCtx->currentIndex + STUN_ATTRIBUTE_HEADER_LENGTH_OFFSET ] ),
                                attributeValueLength );
        }

        pCtx->currentIndex += STUN_ATTRIBUTE_TOTAL_LENGTH( attributeValueLength );
    }

    return result;
}
/*-----------------------------------------------------------*/

static StunResult_t AddAttributeU32( StunContext_t * pCtx,
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
    }

    if( result == STUN_RESULT_OK )
    {
        /* Update flags. */
        if( attributeType == STUN_ATTRIBUTE_TYPE_FINGERPRINT )
        {
            pCtx->attributeFlag |= STUN_FLAG_FINGERPRINT_ATTRIBUTE;
        }
        if( attributeType == STUN_ATTRIBUTE_TYPE_MESSAGE_INTEGRITY )
        {
            pCtx->attributeFlag |= STUN_FLAG_INTEGRITY_ATTRIBUTE;
        }

        if ( pCtx->pStart )
        {
            /* Write Attribute type, length and value. */
            STUN_WRITE_UINT16( (uint8_t *) &( pCtx->pStart[ pCtx->currentIndex ] ),
                                attributeType );

            STUN_WRITE_UINT16( (uint8_t *) &( pCtx->pStart[ pCtx->currentIndex + STUN_ATTRIBUTE_HEADER_LENGTH_OFFSET ] ),
                                attributeValueLength );

            STUN_WRITE_UINT32( (uint8_t *) &( pCtx->pStart[ pCtx->currentIndex + STUN_ATTRIBUTE_HEADER_VALUE_OFFSET ] ),
                                attributeValue );
        }

        pCtx->currentIndex += STUN_ATTRIBUTE_TOTAL_LENGTH( attributeValueLength );
    }

    return result;
}
/*-----------------------------------------------------------*/

static StunResult_t AddAttributeU64( StunContext_t * pCtx,
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
    }

    if( result == STUN_RESULT_OK )
    {
        /* Update flags. */
        if( attributeType == STUN_ATTRIBUTE_TYPE_FINGERPRINT )
        {
            pCtx->attributeFlag |= STUN_FLAG_FINGERPRINT_ATTRIBUTE;
        }
        if( attributeType == STUN_ATTRIBUTE_TYPE_MESSAGE_INTEGRITY )
        {
            pCtx->attributeFlag |= STUN_FLAG_INTEGRITY_ATTRIBUTE;
        }

        if( pCtx->pStart != NULL )
        {
            /* Write Attribute type, length and value. */
            STUN_WRITE_UINT16( (uint8_t *) &( pCtx->pStart[ pCtx->currentIndex ] ),
                                attributeType );

            STUN_WRITE_UINT16( (uint8_t *) &( pCtx->pStart[ pCtx->currentIndex + STUN_ATTRIBUTE_HEADER_LENGTH_OFFSET ] ),
                                attributeValueLength );

            STUN_WRITE_UINT64( (uint8_t *) &( pCtx->pStart[ pCtx->currentIndex + STUN_ATTRIBUTE_HEADER_VALUE_OFFSET ] ),
                                attributeValue );
        }

        pCtx->currentIndex += STUN_ATTRIBUTE_TOTAL_LENGTH( attributeValueLength );
    }

    return result;
}
/*-----------------------------------------------------------*/

static void StunSerializer_InitEndianness( StunContext_t * pCtx )
{
    uint8_t littleEndian;

    littleEndian = ( *( uint8_t * )( &( uint16_t ){ 1 } ) == 1 );

    if ( littleEndian )
    {
        pCtx->readWriteFn.WriteU16Fn = writeUINT16Swap;
        pCtx->readWriteFn.WriteU32Fn = writeUINT32Swap;
        pCtx->readWriteFn.WriteU64Fn = writeUINT64Swap;
        pCtx->readWriteFn.ReadU16Fn = readUINT16Swap;
        pCtx->readWriteFn.ReadU32Fn = readUINT32Swap;
        pCtx->readWriteFn.ReadU64Fn = readUINT64Swap;
    }
    else
    {
        pCtx->readWriteFn.WriteU16Fn = writeUINT16NoSwap;
        pCtx->readWriteFn.WriteU32Fn = writeUINT32NoSwap;
        pCtx->readWriteFn.WriteU64Fn = writeUINT64NoSwap;
        pCtx->readWriteFn.ReadU16Fn = readUINT16NoSwap;
        pCtx->readWriteFn.ReadU32Fn = readUINT32NoSwap;
        pCtx->readWriteFn.ReadU64Fn = readUINT64NoSwap;
    }
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
        StunSerializer_InitEndianness( pCtx );
        pCtx->pStart = pBuffer;
        pCtx->totalLength = bufferLength;
        pCtx->currentIndex = 0;
        pCtx->attributeFlag = 0;

        if ( pCtx->pStart != NULL )
        {
            STUN_WRITE_UINT16( (uint8_t *) &( pCtx->pStart[ pCtx->currentIndex ] ),
                                pHeader->messageType );

            /* Message length is updated in finalize. */
            STUN_WRITE_UINT16( (uint8_t *) &( pCtx->pStart[ pCtx->currentIndex + STUN_HEADER_MESSAGE_LENGTH_OFFSET ] ),
                                0 );

            STUN_WRITE_UINT32( (uint8_t *) &( pCtx->pStart[ pCtx->currentIndex + STUN_HEADER_MAGIC_COOKIE_OFFSET ] ),
                                STUN_HEADER_MAGIC_COOKIE );

            memcpy( ( void * ) &( pCtx->pStart[ pCtx->currentIndex + STUN_HEADER_TRANSACTION_ID_OFFSET ] ),
                    &( pHeader->pTransactionId[ 0 ] ),
                    STUN_HEADER_TRANSACTION_ID_LENGTH );
        }

        pCtx->currentIndex += STUN_HEADER_LENGTH;
    }

    return result;
}
/*-----------------------------------------------------------*/

StunResult_t StunSerializer_XorIpAddress( StunContext_t * pCtx,
                                          StunAttributeAddress_t *ipAddress,
                                          uint8_t * transactionId )
{
    StunResult_t result = STUN_RESULT_OK;
    uint16_t msbMAGIC = (STUN_HEADER_MAGIC_COOKIE >> 16), msbMAGICnew;
    uint32_t data;
    uint8_t *pData, i;

    if ( ipAddress == NULL ||
        ( ipAddress->family != STUN_ADDRESS_IPv4 &&
          ipAddress->family != STUN_ADDRESS_IPv6 ) )
    {
        result = STUN_RESULT_BAD_PARAM;
    }

    if( result == STUN_RESULT_OK )
    {
        STUN_READ_UINT16( &msbMAGICnew, (uint8_t *) &msbMAGIC );
        ipAddress->port = (msbMAGICnew) ^ ipAddress->port;

        //Calculate XORed address
        STUN_READ_UINT32( &data, ipAddress->address);
        data ^= STUN_HEADER_MAGIC_COOKIE;
        STUN_WRITE_UINT32( ipAddress->address, data);

        if (ipAddress->family == STUN_ADDRESS_IPv6 )
        {
            // Process the rest of 12 bytes
            pData = &ipAddress->address[ STUN_IPV4_ADDRESS_SIZE ];
            for (i = 0; i < STUN_HEADER_TRANSACTION_ID_LENGTH; i++)
            {
                *pData++ ^= *transactionId++;
            }
        }
    }

    return result;
}
/*-----------------------------------------------------------*/

StunResult_t StunSerializer_AddAttributeAddress( StunContext_t * pCtx,
                                                 StunAttributeAddress_t *pstunMappedAddress,
                                                 uint8_t * transactionId,
                                                 StunAttributeType_t attributeType )
{
    StunResult_t result = STUN_RESULT_OK;
    uint16_t length = 0;

    if ( pstunMappedAddress == NULL ||
        ( pstunMappedAddress->family != STUN_ADDRESS_IPv4 &&
          pstunMappedAddress->family != STUN_ADDRESS_IPv6 ) )
    {
        result = STUN_RESULT_BAD_PARAM;
    }

    if( result == STUN_RESULT_OK &&
        pCtx->pStart != NULL &&
        ( attributeType == STUN_ATTRIBUTE_TYPE_XOR_MAPPED_ADDRESS ||
          attributeType == STUN_ATTRIBUTE_TYPE_XOR_RELAYED_ADDRESS ||
          attributeType == STUN_ATTRIBUTE_TYPE_XOR_PEER_ADDRESS ))
    {
            StunSerializer_XorIpAddress(pCtx, pstunMappedAddress, transactionId);
    }

    if( result == STUN_RESULT_OK )
    {
        length = STUN_ATTRIBUTE_ADDRESS_HEADER_LENGTH +
                    ((pstunMappedAddress->family == STUN_ADDRESS_IPv4) ? STUN_IPV4_ADDRESS_SIZE : STUN_IPV6_ADDRESS_SIZE);

        STUN_WRITE_UINT16( (uint8_t *) &( pstunMappedAddress->family ),
                            pstunMappedAddress->family );

        result = AddAttributeBuffer( pCtx,
                                     attributeType,
                                     ( const uint8_t * ) pstunMappedAddress,
                                     length );
    }

    return result;
}
/*-----------------------------------------------------------*/

StunResult_t StunSerializer_AddAttributeErrorCode( StunContext_t * pCtx,
                                                   uint16_t errorCode,
                                                   uint8_t * errorPhrase,
                                                   uint16_t errorPhraseLength )
{
    StunResult_t result = STUN_RESULT_OK;
    uint16_t attributeValueLength = STUN_ERROR_CODE_PACKET_ERROR_PHRASE_OFFSET + errorPhraseLength;
    uint16_t attributeValueLengthPadded = STUN_ALIGN_SIZE_TO_WORD( attributeValueLength );
    uint16_t reserved = 0x0;

    if( pCtx == NULL ||
        ( errorPhrase == NULL ) ||
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
        if( ( pCtx->attributeFlag & STUN_FLAG_FINGERPRINT_ATTRIBUTE ) != 0 ||
            ( pCtx->attributeFlag & STUN_FLAG_INTEGRITY_ATTRIBUTE ) != 0 )
        {
            /* No more attributes can be added after Fingerprint or Integrity */
            result = STUN_RESULT_INVALID_ATTRIBUTE_ORDER;
        }
    }

    if( result == STUN_RESULT_OK )
    {
        if ( pCtx->pStart != NULL )
        {
            /* Write Attribute type, length and value. */
            STUN_WRITE_UINT16( (uint8_t *) &( pCtx->pStart[ pCtx->currentIndex ] ),
                                STUN_ATTRIBUTE_TYPE_ERROR_CODE );

            STUN_WRITE_UINT16( (uint8_t *) &( pCtx->pStart[ pCtx->currentIndex + STUN_ATTRIBUTE_HEADER_LENGTH_OFFSET ] ),
                                attributeValueLength );

            /* Reserved bit set to zero */
            STUN_WRITE_UINT16( (uint8_t *) &( pCtx->pStart[ pCtx->currentIndex + STUN_ATTRIBUTE_HEADER_VALUE_OFFSET ] ),
                                reserved );

            STUN_WRITE_UINT16( (uint8_t *) &( pCtx->pStart[ pCtx->currentIndex + STUN_ATTRIBUTE_HEADER_VALUE_OFFSET + STUN_ERROR_CODE_PACKET_ERROR_CLASS_OFFSET ] ),
                                errorCode );

            memcpy( ( void * ) &( pCtx->pStart[ pCtx->currentIndex + STUN_ATTRIBUTE_HEADER_VALUE_OFFSET + STUN_ERROR_CODE_PACKET_ERROR_PHRASE_OFFSET ] ),
                    errorPhrase,
                    errorPhraseLength );

            /* Zero out the padded bytes. */
            if( attributeValueLengthPadded > attributeValueLength )
            {
                memset( ( void * ) &( pCtx->pStart[ pCtx->currentIndex + STUN_ATTRIBUTE_TOTAL_LENGTH( attributeValueLength ) ] ),
                        0,
                        attributeValueLengthPadded - attributeValueLength );
            }
        }

        pCtx->currentIndex += STUN_ATTRIBUTE_TOTAL_LENGTH( attributeValueLength );
    }

    return result;
}
/*-----------------------------------------------------------*/

StunResult_t StunSerializer_AddAttributeChannelNumber( StunContext_t * pCtx,
                                                       StunAttributeType_t attributeType,
                                                       uint16_t channelNumber )
{
    StunResult_t result = STUN_RESULT_OK;
    uint16_t attributeValueLength = STUN_ATTRIBUTE_CHANNEL_NUMBER_LENGTH;
    uint16_t reserved = 0;

    if( pCtx == NULL ||
        attributeType != STUN_ATTRIBUTE_TYPE_CHANNEL_NUMBER )
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
        if( ( pCtx->attributeFlag & STUN_FLAG_FINGERPRINT_ATTRIBUTE ) != 0 ||
            ( pCtx->attributeFlag & STUN_FLAG_INTEGRITY_ATTRIBUTE ) != 0 )
        {
            /* No more attributes can be added after Fingerprint & Integrity.  */
            result = STUN_RESULT_INVALID_ATTRIBUTE_ORDER;
        }
    }

    if( result == STUN_RESULT_OK )
    {
        if( pCtx->pStart != NULL )
        {
            /* Write Attribute type, length and value. */
            STUN_WRITE_UINT16( (uint8_t *) &( pCtx->pStart[ pCtx->currentIndex ] ),
                                attributeType );

            STUN_WRITE_UINT16( (uint8_t *) &( pCtx->pStart[ pCtx->currentIndex + STUN_ATTRIBUTE_HEADER_LENGTH_OFFSET ] ),
                                attributeValueLength );

            STUN_WRITE_UINT16( (uint8_t *) &( pCtx->pStart[ pCtx->currentIndex + STUN_ATTRIBUTE_HEADER_VALUE_OFFSET ] ),
                                channelNumber );

            STUN_WRITE_UINT16( (uint8_t *) &( pCtx->pStart[ pCtx->currentIndex + STUN_ATTRIBUTE_HEADER_VALUE_OFFSET ] ),
                                reserved );
        }

        pCtx->currentIndex += STUN_ATTRIBUTE_TOTAL_LENGTH( attributeValueLength );
    }

    return result;
}
/*-----------------------------------------------------------*/

StunResult_t StunSerializer_AddAttributeUseCandidate( StunContext_t * pCtx )
{
    return AddAttributeFlag( pCtx,
                             STUN_ATTRIBUTE_TYPE_USE_CANDIDATE );
}
/*-----------------------------------------------------------*/

StunResult_t StunSerializer_AddAttributeDontFragment( StunContext_t * pCtx )
{
    return AddAttributeFlag( pCtx,
                             STUN_ATTRIBUTE_TYPE_DONT_FRAGMENT );
}
/*-----------------------------------------------------------*/

StunResult_t StunSerializer_AddAttributePriority( StunContext_t * pCtx,
                                                  uint32_t priority )
{
    return AddAttributeU32( pCtx,
                            STUN_ATTRIBUTE_TYPE_PRIORITY,
                            priority );
}
/*-----------------------------------------------------------*/

StunResult_t StunSerializer_AddAttributeFingerprint( StunContext_t * pCtx,
                                                  uint32_t crc32Fingerprint )
{
    return AddAttributeU32( pCtx,
                            STUN_ATTRIBUTE_TYPE_FINGERPRINT,
                            crc32Fingerprint );
}
/*-----------------------------------------------------------*/

StunResult_t StunSerializer_AddAttributeLifetime( StunContext_t * pCtx,
                                                  uint32_t lifetime )
{
    return AddAttributeU32( pCtx,
                            STUN_ATTRIBUTE_TYPE_LIFETIME,
                            lifetime );
}
/*-----------------------------------------------------------*/

StunResult_t StunSerializer_AddAttributeChangeRequest( StunContext_t * pCtx,
                                                       uint32_t changeFlag )
{
    return AddAttributeU32( pCtx,
                            STUN_ATTRIBUTE_TYPE_CHANGE_REQUEST,
                            changeFlag );
}
/*-----------------------------------------------------------*/

StunResult_t StunSerializer_AddAttributeIceControlled( StunContext_t * pCtx,
                                                       uint64_t tieBreaker )
{
    return AddAttributeU64( pCtx,
                            STUN_ATTRIBUTE_TYPE_ICE_CONTROLLED,
                            tieBreaker );
}
/*-----------------------------------------------------------*/

StunResult_t StunSerializer_AddAttributeIceControlling( StunContext_t * pCtx,
                                                        uint64_t tieBreaker )
{
    return AddAttributeU64( pCtx,
                            STUN_ATTRIBUTE_TYPE_ICE_CONTROLLING,
                            tieBreaker );
}
/*-----------------------------------------------------------*/

StunResult_t StunSerializer_AddAttributeUsername( StunContext_t * pCtx,
                                                  const char * pUsername,
                                                  uint16_t usernameLength )
{
    return AddAttributeBuffer( pCtx,
                               STUN_ATTRIBUTE_TYPE_USERNAME,
                               ( const uint8_t * ) pUsername,
                               usernameLength );
}
/*-----------------------------------------------------------*/

StunResult_t StunSerializer_AddAttributeData( StunContext_t * pCtx,
                                              const char * pData,
                                              uint16_t dataLength )
{
    return AddAttributeBuffer( pCtx,
                               STUN_ATTRIBUTE_TYPE_DATA,
                               ( const uint8_t * ) pData,
                               dataLength );
}
/*-----------------------------------------------------------*/

StunResult_t StunSerializer_AddAttributeRealm( StunContext_t * pCtx,
                                               const char * pRealm,
                                               uint16_t realmLength )
{
    return AddAttributeBuffer( pCtx,
                               STUN_ATTRIBUTE_TYPE_REALM,
                               ( const uint8_t * ) pRealm,
                               realmLength );
}
/*-----------------------------------------------------------*/

StunResult_t StunSerializer_AddAttributeNonce( StunContext_t * pCtx,
                                               const char * pNonce,
                                               uint16_t nonceLength )
{
    return AddAttributeBuffer( pCtx,
                               STUN_ATTRIBUTE_TYPE_NONCE,
                               ( const uint8_t * ) pNonce,
                               nonceLength );
}
/*-----------------------------------------------------------*/

StunResult_t StunSerializer_AddAttributeRequestedTransport( StunContext_t * pCtx,
                                                            const char * pRequestedTransport,
                                                            uint16_t requestedTransportLength )
{
    return AddAttributeBuffer( pCtx,
                               STUN_ATTRIBUTE_TYPE_REQUESTED_TRANSPORT,
                               ( const uint8_t * ) pRequestedTransport,
                               requestedTransportLength );
}
/*-----------------------------------------------------------*/

StunResult_t StunSerializer_AddAttributeIntegrity( StunContext_t * pCtx,
                                                   const char * pIntegrity,
                                                   uint16_t integrityLength )
{
    return AddAttributeBuffer( pCtx,
                               STUN_ATTRIBUTE_TYPE_MESSAGE_INTEGRITY,
                               ( const uint8_t * ) pIntegrity,
                               integrityLength );
}
/*-----------------------------------------------------------*/

StunResult_t StunSerializer_AddAttributeMappedAddress( StunContext_t * pCtx,
                                                       StunAttributeAddress_t *pstunMappedAddress,
                                                       uint8_t * pTransactionId )
{
    return StunSerializer_AddAttributeAddress( pCtx,
                                               pstunMappedAddress,
                                               pTransactionId,
                                               STUN_ATTRIBUTE_TYPE_MAPPED_ADDRESS );
}
/*-----------------------------------------------------------*/

StunResult_t StunSerializer_AddAttributeResponseAddress( StunContext_t * pCtx,
                                                         StunAttributeAddress_t *pstunMappedAddress,
                                                         uint8_t * pTransactionId )
{
    return StunSerializer_AddAttributeAddress( pCtx,
                                               pstunMappedAddress,
                                               pTransactionId,
                                               STUN_ATTRIBUTE_TYPE_RESPONSE_ADDRESS );
}
/*-----------------------------------------------------------*/

StunResult_t StunSerializer_AddAttributeSourceAddress( StunContext_t * pCtx,
                                                       StunAttributeAddress_t *pstunMappedAddress,
                                                       uint8_t * pTransactionId )
{
    return StunSerializer_AddAttributeAddress( pCtx,
                                               pstunMappedAddress,
                                               pTransactionId,
                                               STUN_ATTRIBUTE_TYPE_SOURCE_ADDRESS );
}
/*-----------------------------------------------------------*/

StunResult_t StunSerializer_AddAttributeChangedAddress( StunContext_t * pCtx,
                                                        StunAttributeAddress_t *pstunMappedAddress,
                                                        uint8_t * pTransactionId )
{
    return StunSerializer_AddAttributeAddress( pCtx,
                                               pstunMappedAddress,
                                               pTransactionId,
                                               STUN_ATTRIBUTE_TYPE_CHANGED_ADDRESS );
}
/*-----------------------------------------------------------*/

StunResult_t StunSerializer_AddAttributeChangedReflectedFrom( StunContext_t * pCtx,
                                                              StunAttributeAddress_t *pstunMappedAddress,
                                                              uint8_t * pTransactionId )
{
    return StunSerializer_AddAttributeAddress( pCtx,
                                               pstunMappedAddress,
                                               pTransactionId,
                                               STUN_ATTRIBUTE_TYPE_REFLECTED_FROM );
}
/*-----------------------------------------------------------*/

StunResult_t StunSerializer_AddAttributeXORMappedAddress( StunContext_t * pCtx,
                                                          StunAttributeAddress_t *pstunMappedAddress,
                                                          uint8_t * pTransactionId )
{
    return StunSerializer_AddAttributeAddress( pCtx,
                                               pstunMappedAddress,
                                               pTransactionId,
                                               STUN_ATTRIBUTE_TYPE_XOR_MAPPED_ADDRESS );
}
/*-----------------------------------------------------------*/

StunResult_t StunSerializer_AddAttributeXORPeerAddress( StunContext_t * pCtx,
                                                        StunAttributeAddress_t *pstunMappedAddress,
                                                        uint8_t * pTransactionId )
{
    return StunSerializer_AddAttributeAddress( pCtx,
                                               pstunMappedAddress,
                                               pTransactionId,
                                               STUN_ATTRIBUTE_TYPE_XOR_PEER_ADDRESS );
}
/*-----------------------------------------------------------*/

StunResult_t StunSerializer_AddAttributeXORRelayedAddress( StunContext_t * pCtx,
                                                           StunAttributeAddress_t *pstunMappedAddress,
                                                           uint8_t * pTransactionId )
{
    return StunSerializer_AddAttributeAddress( pCtx,
                                               pstunMappedAddress,
                                               pTransactionId,
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
        if ( pCtx->pStart != NULL )
        {
            // Fix-up the packet length with message integrity and without the STUN header
            STUN_WRITE_UINT16( (uint8_t *) &( pCtx->pStart[ STUN_HEADER_MESSAGE_LENGTH_OFFSET ] ),
                                pCtx->currentIndex - STUN_HEADER_LENGTH + STUN_ATTRIBUTE_TOTAL_LENGTH( STUN_HMAC_VALUE_LENGTH ));

            *ppStunMessage =  (uint8_t *) (pCtx->pStart);
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
        if ( pCtx->pStart != NULL )
        {
            // Fix-up the packet length with fingerprint CRC and without the STUN header
            STUN_WRITE_UINT16( (uint8_t *) &( pCtx->pStart[ STUN_HEADER_MESSAGE_LENGTH_OFFSET ] ),
                                pCtx->currentIndex - STUN_HEADER_LENGTH + STUN_ATTRIBUTE_TOTAL_LENGTH( STUN_ATTRIBUTE_FINGERPRINT_LENGTH ));

            *ppStunMessage =  (uint8_t *) (pCtx->pStart);
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
        if ( pCtx->pStart != NULL )
        {
            /* Update the message length field in the header. */
            STUN_WRITE_UINT16( (uint8_t *) &( pCtx->pStart[ STUN_HEADER_MESSAGE_LENGTH_OFFSET ] ),
                                pCtx->currentIndex - STUN_HEADER_LENGTH );
        }
        *pStunMessageLength = pCtx->currentIndex;

    }

    return result;
}
/*-----------------------------------------------------------*/
