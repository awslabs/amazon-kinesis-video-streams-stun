/* Standard includes. */
#include <stdio.h>
#include <string.h>

/* API includes. */
#include "stun_deserializer.h"

/* Static Functions */
static StunResult_t StunDeserializer_ParseAttributeUINT32( const StunAttribute_t * pAttribute,
                                                           uint32_t * val,
                                                           StunAttributeType_t attributeType );

static StunResult_t StunDeserializer_ParseAttributeUINT64( const StunAttribute_t * pAttribute,
                                                           uint64_t * val,
                                                           StunAttributeType_t attributeType );

static StunResult_t StunDeserializer_ParseAttributeAddress( const StunAttribute_t * pAttribute,
                                                            StunAttributeAddress_t **pStunMappedAddress,
                                                            StunAttributeType_t attributeType );

static StunResult_t StunDeserializer_ParseAttributeXORAddress( const StunAttribute_t * pAttribute,
                                                               StunAttributeAddress_t **pStunMappedAddress,
                                                               uint8_t *pTransactionId,
                                                               StunAttributeType_t attributeType );

static StunResult_t StunDeserializer_ParseAttributeBuffer( const StunAttribute_t * pAttribute,
                                                           const char ** pBuffer,
                                                           uint16_t * pBufferLength,
                                                           StunAttributeType_t attributeType );

/*-----------------------------------------------------------*/

static StunResult_t StunDeserializer_ParseAttributeUINT32( const StunAttribute_t * pAttribute,
                                                           uint32_t * val,
                                                           StunAttributeType_t attributeType )
{
    StunResult_t result = STUN_RESULT_OK;

    if( ( pAttribute == NULL ) ||
        ( val == NULL ) ||
        ( pAttribute->attributeType != attributeType ) ||
        ( pAttribute->pAttributeValue == NULL ) )
    {
        result = STUN_RESULT_BAD_PARAM;
    }

    if( result == STUN_RESULT_OK )
    {
        if( pAttribute->attributeValueLength != sizeof( uint32_t ) )
        {
            result = STUN_RESULT_INVALID_ATTRIBUTE_LENGTH;
        }
    }

    if( result == STUN_RESULT_OK )
    {
        READ_UINT32( val, (uint8_t *) &( *( ( uint32_t * ) pAttribute->pAttributeValue ) ) );
    }

    return result;
}
/*-----------------------------------------------------------*/

static StunResult_t StunDeserializer_ParseAttributeUINT64( const StunAttribute_t * pAttribute,
                                                           uint64_t * val,
                                                           StunAttributeType_t attributeType )
{
    StunResult_t result = STUN_RESULT_OK;

    if( ( pAttribute == NULL ) ||
        ( val == NULL ) ||
        ( pAttribute->attributeType != attributeType ) ||
        ( pAttribute->pAttributeValue == NULL ) )
    {
        result = STUN_RESULT_BAD_PARAM;
    }

    if( result == STUN_RESULT_OK )
    {
        if( pAttribute->attributeValueLength != sizeof( uint64_t ) )
        {
            result = STUN_RESULT_INVALID_ATTRIBUTE_LENGTH;
        }
    }

    if( result == STUN_RESULT_OK )
    {
        READ_UINT64( val, (uint8_t *) &( *( ( uint64_t * ) pAttribute->pAttributeValue ) ) );
    }

    return result;
}
/*-----------------------------------------------------------*/

static StunResult_t StunDeserializer_ParseAttributeBuffer( const StunAttribute_t * pAttribute,
                                                           const char ** pBuffer,
                                                           uint16_t * pBufferLength,
                                                           StunAttributeType_t attributeType )
{
    StunResult_t result = STUN_RESULT_OK;

    if( ( pAttribute == NULL ) ||
        ( pBufferLength == NULL ) ||
        ( pAttribute->pAttributeValue == NULL ) ||
        ( pAttribute->attributeType != attributeType ) )
    {
        result = STUN_RESULT_BAD_PARAM;
    }

    if( result == STUN_RESULT_OK )
    {
        *pBuffer = ( const char * ) pAttribute->pAttributeValue;
        *pBufferLength = pAttribute->attributeValueLength;
    }

    return result;
}
/*-----------------------------------------------------------*/

static StunResult_t StunDeserializer_ParseAttributeAddress( const StunAttribute_t * pAttribute,
                                                            StunAttributeAddress_t **pStunMappedAddress,
                                                            StunAttributeType_t attributeType )
{
    StunResult_t result = STUN_RESULT_OK;

     if( ( pAttribute == NULL ) ||
        ( pAttribute->pAttributeValue == NULL ) ||
        ( pAttribute->attributeType != attributeType ) )
    {
        result = STUN_RESULT_BAD_PARAM;
    }

    if( result == STUN_RESULT_OK )
    {
        *pStunMappedAddress = ( StunAttributeAddress_t * ) pAttribute->pAttributeValue;
    }

    return result;
}
/*-----------------------------------------------------------*/

static StunResult_t StunDeserializer_ParseAttributeXORAddress( const StunAttribute_t * pAttribute,
                                                               StunAttributeAddress_t **pStunMappedAddress,
                                                               uint8_t *pTransactionId,
                                                               StunAttributeType_t attributeType )
{
    StunResult_t result = STUN_RESULT_OK;
    uint16_t msbMAGIC = (STUN_HEADER_MAGIC_COOKIE >> 16);
    uint16_t port;
    StunAttributeAddress_t *pXorAddress;
    uint8_t *pData, i;
    uint32_t data;

    if( ( pAttribute == NULL ) ||
        ( pAttribute->pAttributeValue == NULL ) ||
        ( pAttribute->attributeType != attributeType ) )
    {
        result = STUN_RESULT_BAD_PARAM;
    }

    if( result == STUN_RESULT_OK )
    {
        pXorAddress = ( StunAttributeAddress_t * ) pAttribute->pAttributeValue;

        // Calulate XORed port
        READ_UINT16( &port, (uint8_t *) &pXorAddress->port );
        port ^= (uint16_t) msbMAGIC;
        pXorAddress->port = port;

        //Calculate XORed address
        READ_UINT32( &data, (uint8_t *) &pXorAddress->address );
        data ^= STUN_HEADER_MAGIC_COOKIE;
        WRITE_UINT32( (uint8_t *) &pXorAddress->address, data );

        if ( pXorAddress->family == STUN_ADDRESS_IPv6 )
        {
            // Process the rest of 12 bytes
            pData = &pXorAddress->address[ STUN_IPV4_ADDRESS_SIZE ];
            for (i = 0; i < STUN_HEADER_TRANSACTION_ID_LENGTH; i++)
            {
                *pData++ ^= *pTransactionId++;
            }
        }

        *pStunMappedAddress = pXorAddress;
    }

    return result;
}
/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_Init( StunContext_t * pCtx,
                                    const uint8_t * pStunMessage,
                                    size_t stunMessageLength,
                                    StunHeader_t * pStunHeader )
{
    StunResult_t result = STUN_RESULT_OK;
    uint32_t magicCookie;
    uint16_t messageLengthInHeader;

    init_endianness();

    if( ( pCtx == NULL ) ||
        ( pStunMessage == NULL ) ||
        ( stunMessageLength < STUN_HEADER_LENGTH ) ||
        ( pStunHeader == NULL ) )
    {
        result = STUN_RESULT_BAD_PARAM;
    }

    if( result == STUN_RESULT_OK )
    {
        pCtx->pStart = pStunMessage;
        pCtx->totalLength = stunMessageLength;
        pCtx->currentIndex = 0;
        pCtx->flags = 0;

        READ_UINT16( ( uint16_t * ) &( pStunHeader->messageType ),
                     ( uint8_t * ) &( pCtx->pStart[ pCtx->currentIndex ] ) );
        READ_UINT16( &( messageLengthInHeader ),
                     (uint8_t *) &( pCtx->pStart[ pCtx->currentIndex + STUN_HEADER_MESSAGE_LENGTH_OFFSET ] ) );
        READ_UINT32( &magicCookie,
                     ( uint8_t * ) &( pCtx->pStart[ pCtx->currentIndex + STUN_HEADER_MAGIC_COOKIE_OFFSET ] ) );

        if( magicCookie != STUN_HEADER_MAGIC_COOKIE )
        {
            result = STUN_RESULT_MAGIC_COOKIE_MISMATCH;
        }
        else if( ( messageLengthInHeader + STUN_HEADER_LENGTH ) != stunMessageLength )
        {
            result = STUN_RESULT_MALFORMED_MESSAGE;
        }
        else
        {
            memcpy( &( pStunHeader->transactionId[ 0 ] ),
                    &( pCtx->pStart[ pCtx->currentIndex + STUN_HEADER_TRANSACTION_ID_OFFSET ] ),
                    STUN_HEADER_TRANSACTION_ID_LENGTH );

            pCtx->currentIndex += STUN_HEADER_LENGTH;
        }
    }

    return result;
}
/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_GetNextAttribute( StunContext_t * pCtx,
                                                StunAttribute_t * pAttribute )
{
    StunResult_t result = STUN_RESULT_OK;
    uint16_t attributeType;

    if( ( pCtx == NULL ) ||
        ( pAttribute == NULL ) )
    {
        result = STUN_RESULT_BAD_PARAM;
    }

    if( result == STUN_RESULT_OK )
    {
        if( REMAINING_LENGTH( pCtx ) < STUN_ATTRIBUTE_HEADER_LENGTH )
        {
            result = STUN_RESULT_NO_MORE_ATTRIBUTE_FOUND;
        }
    }

    if( result == STUN_RESULT_OK )
    {
        /* Read attribute type. */
        READ_UINT16( &attributeType,
                     ( uint8_t * ) &( pCtx->pStart[ pCtx->currentIndex ] ) );
        pAttribute->attributeType = ( StunAttributeType_t ) attributeType;

        /* Check that it is correct attribute at this position. */
        if( ( pCtx->flags & STUN_FLAG_FINGERPRINT_ATTRIBUTE ) != 0 )
        {
            /* No more attributes can be present after Fingerprint - it must  be
             * the last attribute. */
            result = STUN_RESULT_INVALID_ATTRIBUTE_ORDER;
        }
        else if( ( ( pCtx->flags & STUN_FLAG_INTEGRITY_ATTRIBUTE ) != 0 ) &&
                 ( pAttribute->attributeType != STUN_ATTRIBUTE_TYPE_FINGERPRINT ) )
        {
            /* No attribute other than fingerprint can be present after
             * Integrity attribute. */
            result = STUN_RESULT_INVALID_ATTRIBUTE_ORDER;
        }
    }

    if( result == STUN_RESULT_OK )
    {
        if( pAttribute->attributeType == STUN_ATTRIBUTE_TYPE_FINGERPRINT )
        {
            pCtx->flags |= STUN_FLAG_FINGERPRINT_ATTRIBUTE;
        }
        if( pAttribute->attributeType == STUN_ATTRIBUTE_TYPE_MESSAGE_INTEGRITY )
        {
            pCtx->flags |= STUN_FLAG_INTEGRITY_ATTRIBUTE;
        }

        /* Read attribute length. */
        READ_UINT16( &( pAttribute->attributeValueLength ),
                     ( uint8_t * ) &( pCtx->pStart[ pCtx->currentIndex + STUN_ATTRIBUTE_HEADER_LENGTH_OFFSET ] ) );

        /* Check that we have enough data to read attribute value. */
        if( REMAINING_LENGTH( pCtx ) < STUN_ATTRIBUTE_TOTAL_LENGTH( pAttribute->attributeValueLength ) )
        {
            result = STUN_RESULT_MALFORMED_MESSAGE;
        }
    }

    if( result == STUN_RESULT_OK )
    {
        pAttribute->pAttributeValue = &( pCtx->pStart[ pCtx->currentIndex + STUN_ATTRIBUTE_HEADER_VALUE_OFFSET ] );

        pCtx->currentIndex += STUN_ATTRIBUTE_TOTAL_LENGTH( ALIGN_SIZE_TO_WORD( pAttribute->attributeValueLength ) );
    }

    return result;
}
/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_ParseAttributeErrorCode( const StunAttribute_t * pAttribute,
                                                       uint16_t * errorCode,
                                                       uint8_t ** errorPhrase )
{
    StunResult_t result = STUN_RESULT_OK;
    uint8_t class, errorNumber;
    uint16_t errorPhaseLength = pAttribute->attributeValueLength - STUN_ERROR_CODE_PACKET_ERROR_PHRASE_OFFSET;

    if( ( pAttribute == NULL ) ||
        ( errorCode == NULL ) ||
        ( pAttribute->pAttributeValue == NULL ) ||
        ( errorPhaseLength <= 0 ) ||
        ( pAttribute->attributeType != STUN_ATTRIBUTE_TYPE_ERROR_CODE ) )
    {
        result = STUN_RESULT_BAD_PARAM;
    }

    if( result == STUN_RESULT_OK )
    {
        class = pAttribute->pAttributeValue[STUN_ERROR_CODE_PACKET_ERROR_CLASS_OFFSET];
        errorNumber = pAttribute->pAttributeValue[STUN_ERROR_CODE_PACKET_ERROR_CODE_OFFSET];

        *errorCode = GET_STUN_ERROR_CODE( class,
                                          errorNumber );
        *errorPhrase = (uint8_t *)&pAttribute->pAttributeValue[STUN_ERROR_CODE_PACKET_ERROR_PHRASE_OFFSET];
    }
    return result;
}

/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_ParseAttributeChannelNumber( const StunAttribute_t * pAttribute,
                                                           uint16_t * channelNumber,
                                                           StunAttributeType_t attributeType )
{
    StunResult_t result = STUN_RESULT_OK;

    if( ( pAttribute == NULL ) ||
        ( channelNumber == NULL ) ||
        ( pAttribute->attributeType != attributeType ) ||
        ( pAttribute->pAttributeValue == NULL ) )
    {
        result = STUN_RESULT_BAD_PARAM;
    }

    if( result == STUN_RESULT_OK )
    {
        if( pAttribute->attributeValueLength != STUN_ATTRIBUTE_CHANNEL_NUMBER_LENGTH )
        {
            result = STUN_RESULT_INVALID_ATTRIBUTE_LENGTH;
        }
    }

    if( result == STUN_RESULT_OK )
    {
        READ_UINT16( channelNumber, (uint8_t *) &( *( ( uint16_t * ) pAttribute->pAttributeValue ) ) );
    }

    return result;
}
/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_ParseAttributeUseCandidate( StunContext_t * pCtx,
                                                          const StunAttribute_t * pAttribute,
                                                          StunAttributeType_t attributeType )
{
    StunResult_t result = STUN_RESULT_OK;

    if( ( pAttribute == NULL ) ||
        ( pAttribute->attributeType != attributeType ) ||
        ( pAttribute->pAttributeValue != NULL ) )
    {
        result = STUN_RESULT_BAD_PARAM;
    }

    if( result == STUN_RESULT_OK )
    {
        if( pAttribute->attributeValueLength != 0 )
        {
            result = STUN_RESULT_INVALID_ATTRIBUTE_LENGTH;
        }
    }

    if( result == STUN_RESULT_OK )
    {
        pCtx->flags |= STUN_FLAG_USE_CANDIDATE_ATTRIBUTE;
    }

    return result;
}
/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_ParseAttributeDontFragment( StunContext_t * pCtx,
                                                          const StunAttribute_t * pAttribute,
                                                          StunAttributeType_t attributeType )
{
    StunResult_t result = STUN_RESULT_OK;

    if( ( pAttribute == NULL ) ||
        ( pAttribute->attributeType != attributeType ) ||
        ( pAttribute->pAttributeValue != NULL ) )
    {
        result = STUN_RESULT_BAD_PARAM;
    }

    if( result == STUN_RESULT_OK )
    {
        if( pAttribute->attributeValueLength != 0 )
        {
            result = STUN_RESULT_INVALID_ATTRIBUTE_LENGTH;
        }
    }

    if( result == STUN_RESULT_OK )
    {
        pCtx->flags |= STUN_FLAG_DONT_FRAGMENT_ATTRIBUTE;
    }

    return result;
}
/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_ParseAttributePriority( const StunAttribute_t * pAttribute,
                                                      uint32_t * pPriority )
{
    return StunDeserializer_ParseAttributeUINT32( pAttribute,
                                                  pPriority,
                                                  STUN_ATTRIBUTE_TYPE_PRIORITY );
}
/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_ParseAttributeFingerpint( const StunAttribute_t * pAttribute,
                                                        uint32_t * crc32Fingerprint )
{
    return StunDeserializer_ParseAttributeUINT32( pAttribute,
                                                  crc32Fingerprint,
                                                  STUN_ATTRIBUTE_TYPE_FINGERPRINT );
}
/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_ParseAttributeLifetime( const StunAttribute_t * pAttribute,
                                                        uint32_t * lifetime )
{
    return StunDeserializer_ParseAttributeUINT32( pAttribute,
                                                  lifetime,
                                                  STUN_ATTRIBUTE_TYPE_LIFETIME );
}
/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_ParseAttributeIceControlled( const StunAttribute_t * pAttribute,
                                                           uint64_t * pTieBreaker )
{
    return StunDeserializer_ParseAttributeUINT64( pAttribute,
                                                  pTieBreaker,
                                                  STUN_ATTRIBUTE_TYPE_ICE_CONTROLLED );
}
/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_ParseAttributeIceControlling( const StunAttribute_t * pAttribute,
                                                            uint64_t * pTieBreaker )
{

    return StunDeserializer_ParseAttributeUINT64( pAttribute,
                                                  pTieBreaker,
                                                  STUN_ATTRIBUTE_TYPE_ICE_CONTROLLING );
}
/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_ParseAttributeUsername( const StunAttribute_t * pAttribute,
                                                      const char ** pUsername,
                                                      uint16_t * pUsernameLength )
{
    return StunDeserializer_ParseAttributeBuffer( pAttribute,
                                                  pUsername,
                                                  pUsernameLength,
                                                  STUN_ATTRIBUTE_TYPE_USERNAME );
}
/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_ParseAttributeData( const StunAttribute_t * pAttribute,
                                                  const char ** pData,
                                                  uint16_t * pDataLength )
{
    return StunDeserializer_ParseAttributeBuffer( pAttribute,
                                                  pData,
                                                  pDataLength,
                                                  STUN_ATTRIBUTE_TYPE_DATA );
}
/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_ParseAttributeRealm( const StunAttribute_t * pAttribute,
                                                   const char ** pRealm,
                                                   uint16_t * pRealmLength )
{
    return StunDeserializer_ParseAttributeBuffer( pAttribute,
                                                  pRealm,
                                                  pRealmLength,
                                                  STUN_ATTRIBUTE_TYPE_REALM );
}
/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_ParseAttributeNonce( const StunAttribute_t * pAttribute,
                                                   const char ** pNonce,
                                                   uint16_t * pNonceLength )
{
    return StunDeserializer_ParseAttributeBuffer( pAttribute,
                                                  pNonce,
                                                  pNonceLength,
                                                  STUN_ATTRIBUTE_TYPE_NONCE );
}
/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_ParseAttributeRequestedTransport( const StunAttribute_t * pAttribute,
                                                                const char ** pRequestedTransport,
                                                                uint16_t * pRequestedTransportLength )
{
    return StunDeserializer_ParseAttributeBuffer( pAttribute,
                                                  pRequestedTransport,
                                                  pRequestedTransportLength,
                                                  STUN_ATTRIBUTE_TYPE_REQUESTED_TRANSPORT );
}
/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_ParseAttributeIntegrity( const StunAttribute_t * pAttribute,
                                                       const char ** pIntegrity,
                                                       uint16_t * pIntegrityLength )
{
    return StunDeserializer_ParseAttributeBuffer( pAttribute,
                                                  pIntegrity,
                                                  pIntegrityLength,
                                                  STUN_ATTRIBUTE_TYPE_MESSAGE_INTEGRITY );
}
/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_ParseAttributeMappedAddress( const StunAttribute_t * pAttribute,
                                                           StunAttributeAddress_t **pStunMappedAddress )
{
    return StunDeserializer_ParseAttributeAddress( pAttribute,
                                                   pStunMappedAddress,
                                                   STUN_ATTRIBUTE_TYPE_MAPPED_ADDRESS );
}
/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_ParseAttributeResponseAddress( const StunAttribute_t * pAttribute,
                                                           StunAttributeAddress_t **pStunMappedAddress )
{
    return StunDeserializer_ParseAttributeAddress( pAttribute,
                                                   pStunMappedAddress,
                                                   STUN_ATTRIBUTE_TYPE_RESPONSE_ADDRESS );
}
/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_ParseAttributeSourceAddress( const StunAttribute_t * pAttribute,
                                                           StunAttributeAddress_t **pStunMappedAddress )
{
    return StunDeserializer_ParseAttributeAddress( pAttribute,
                                                   pStunMappedAddress,
                                                   STUN_ATTRIBUTE_TYPE_SOURCE_ADDRESS );
}
/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_ParseAttributeChangedAddress( const StunAttribute_t * pAttribute,
                                                            StunAttributeAddress_t **pStunMappedAddress )
{
    return StunDeserializer_ParseAttributeAddress( pAttribute,
                                                   pStunMappedAddress,
                                                   STUN_ATTRIBUTE_TYPE_CHANGED_ADDRESS );
}
/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_ParseAttributeReflectedFrom( const StunAttribute_t * pAttribute,
                                                           StunAttributeAddress_t **pStunMappedAddress )
{
    return StunDeserializer_ParseAttributeAddress( pAttribute,
                                                   pStunMappedAddress,
                                                   STUN_ATTRIBUTE_TYPE_REFLECTED_FROM );
}
/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_ParseAttributeXORMappedAddress( const StunAttribute_t * pAttribute,
                                                              StunAttributeAddress_t **pStunMappedAddress,
                                                              uint8_t *pTransactionId )
{
    return StunDeserializer_ParseAttributeXORAddress( pAttribute,
                                                      pStunMappedAddress,
                                                      pTransactionId,
                                                      STUN_ATTRIBUTE_TYPE_XOR_MAPPED_ADDRESS );
}
/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_ParseAttributeXORPeerAddress( const StunAttribute_t * pAttribute,
                                                            StunAttributeAddress_t **pStunMappedAddress,
                                                            uint8_t *pTransactionId )
{
    return StunDeserializer_ParseAttributeXORAddress( pAttribute,
                                                      pStunMappedAddress,
                                                      pTransactionId,
                                                      STUN_ATTRIBUTE_TYPE_XOR_PEER_ADDRESS );
}
/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_ParseAttributeXORRelayedAddress( const StunAttribute_t * pAttribute,
                                                               StunAttributeAddress_t **pStunMappedAddress,
                                                               uint8_t *pTransactionId )
{
    return StunDeserializer_ParseAttributeXORAddress( pAttribute,
                                                      pStunMappedAddress,
                                                      pTransactionId,
                                                      STUN_ATTRIBUTE_TYPE_XOR_RELAYED_ADDRESS );
}
/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_IsFlagAttributeFound( const StunContext_t * pCtx,
                                                    StunAttributeType_t attributeType,
                                                    uint16_t *pAttrFound )
{
    StunResult_t result = STUN_RESULT_OK;
    *pAttrFound = 0;

    if ( ( attributeType == STUN_ATTRIBUTE_TYPE_USE_CANDIDATE ) ||
         ( attributeType == STUN_ATTRIBUTE_TYPE_DONT_FRAGMENT ) )
    {
        result = STUN_RESULT_BAD_PARAM;
    }

    if( result == STUN_RESULT_OK )
    {
        if( ( pCtx->flags & attributeType ) == 1 )
        {
            *pAttrFound = 1;
        }
    }
}
/*-----------------------------------------------------------*/