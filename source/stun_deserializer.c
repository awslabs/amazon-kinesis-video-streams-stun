/* Standard includes. */
#include <stdio.h>
#include <string.h>

/* API includes. */
#include "stun_deserializer.h"

/* Read/Write flags. */
#define STUN_WRITE_UINT16   ( pCtx->readWriteFn.WriteU16Fn )
#define STUN_WRITE_UINT32   ( pCtx->readWriteFn.WriteU32Fn )
#define STUN_WRITE_UINT64   ( pCtx->readWriteFn.WriteU64Fn )
#define STUN_READ_UINT16    ( pCtx->readWriteFn.ReadU16Fn )
#define STUN_READ_UINT32    ( pCtx->readWriteFn.ReadU32Fn )
#define STUN_READ_UINT64    ( pCtx->readWriteFn.ReadU64Fn )

/* Static Functions */
static StunResult_t StunDeserializer_ParseAttributeUINT32( const StunContext_t * pCtx,
                                                           const StunAttribute_t * pAttribute,
                                                           uint32_t * val,
                                                           StunAttributeType_t attributeType );

static StunResult_t StunDeserializer_ParseAttributeUINT64( const StunContext_t * pCtx,
                                                           const StunAttribute_t * pAttribute,
                                                           uint64_t * val,
                                                           StunAttributeType_t attributeType );

static StunResult_t StunDeserializer_ParseAttributeBuffer( const StunAttribute_t * pAttribute,
                                                           const char ** ppBuffer,
                                                           uint16_t * pBufferLength,
                                                           StunAttributeType_t attributeType );

static void StunDeserializer_InitEndianness( StunContext_t * pCtx );

/*-----------------------------------------------------------*/

static StunResult_t StunDeserializer_ParseAttributeUINT32( const StunContext_t * pCtx,
                                                           const StunAttribute_t * pAttribute,
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
        STUN_READ_UINT32( val, ( uint8_t * ) &( *( ( uint32_t * ) pAttribute->pAttributeValue ) ) );
    }

    return result;
}
/*-----------------------------------------------------------*/

static StunResult_t StunDeserializer_ParseAttributeUINT64( const StunContext_t * pCtx,
                                                           const StunAttribute_t * pAttribute,
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
        STUN_READ_UINT64( val, ( uint8_t * ) &( *( ( uint64_t * ) pAttribute->pAttributeValue ) ) );
    }

    return result;
}
/*-----------------------------------------------------------*/

static StunResult_t StunDeserializer_ParseAttributeBuffer( const StunAttribute_t * pAttribute,
                                                           const char ** ppBuffer,
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
        *ppBuffer = ( const char * ) pAttribute->pAttributeValue;
        *pBufferLength = pAttribute->attributeValueLength;
    }

    return result;
}
/*-----------------------------------------------------------*/

static void StunDeserializer_InitEndianness( StunContext_t * pCtx )
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

StunResult_t StunDeserializer_Init( StunContext_t * pCtx,
                                    const uint8_t * pStunMessage,
                                    size_t stunMessageLength,
                                    StunHeader_t * pStunHeader )
{
    StunResult_t result = STUN_RESULT_OK;
    uint32_t magicCookie;
    uint16_t messageLengthInHeader;

    if( ( pCtx == NULL ) ||
        ( pStunMessage == NULL ) ||
        ( stunMessageLength < STUN_HEADER_LENGTH ) ||
        ( pStunHeader == NULL ) )
    {
        result = STUN_RESULT_BAD_PARAM;
    }

    if( result == STUN_RESULT_OK )
    {
        StunDeserializer_InitEndianness( pCtx );
        pCtx->pStart = pStunMessage;
        pCtx->totalLength = stunMessageLength;
        pCtx->currentIndex = 0;
        pCtx->attributeFlag = 0;

        STUN_READ_UINT16( ( uint16_t * ) &( pStunHeader->messageType ),
                          ( uint8_t * ) &( pCtx->pStart[ pCtx->currentIndex ] ) );
        STUN_READ_UINT16( &( messageLengthInHeader ),
                          ( uint8_t * ) &( pCtx->pStart[ pCtx->currentIndex + STUN_HEADER_MESSAGE_LENGTH_OFFSET ] ) );
        STUN_READ_UINT32( &magicCookie,
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
            pStunHeader->pTransactionId = ( uint8_t * )  & (pCtx->pStart[ pCtx->currentIndex + STUN_HEADER_TRANSACTION_ID_OFFSET ]);
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
        if( STUN_REMAINING_LENGTH( pCtx ) < STUN_ATTRIBUTE_HEADER_LENGTH )
        {
            result = STUN_RESULT_NO_MORE_ATTRIBUTE_FOUND;
        }
    }

    if( result == STUN_RESULT_OK )
    {
        /* Read attribute type. */
        STUN_READ_UINT16( &attributeType,
                          ( uint8_t * ) &( pCtx->pStart[ pCtx->currentIndex ] ) );
        pAttribute->attributeType = ( StunAttributeType_t ) attributeType;

        /* Check that it is correct attribute at this position. */
        if( ( pCtx->attributeFlag & STUN_FLAG_FINGERPRINT_ATTRIBUTE ) != 0 )
        {
            /* No more attributes can be present after Fingerprint - it must  be
             * the last attribute. */
            result = STUN_RESULT_INVALID_ATTRIBUTE_ORDER;
        }
        else if( ( ( pCtx->attributeFlag & STUN_FLAG_INTEGRITY_ATTRIBUTE ) != 0 ) &&
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
            pCtx->attributeFlag |= STUN_FLAG_FINGERPRINT_ATTRIBUTE;
        }
        if( pAttribute->attributeType == STUN_ATTRIBUTE_TYPE_MESSAGE_INTEGRITY )
        {
            pCtx->attributeFlag |= STUN_FLAG_INTEGRITY_ATTRIBUTE;
        }

        /* Read attribute length. */
        STUN_READ_UINT16( &( pAttribute->attributeValueLength ),
                          ( uint8_t * ) &( pCtx->pStart[ pCtx->currentIndex + STUN_ATTRIBUTE_HEADER_LENGTH_OFFSET ] ) );

        /* Check that we have enough data to read attribute value. */
        if( STUN_REMAINING_LENGTH( pCtx ) < STUN_ATTRIBUTE_TOTAL_LENGTH( pAttribute->attributeValueLength ) )
        {
            result = STUN_RESULT_MALFORMED_MESSAGE;
        }
    }

    if( result == STUN_RESULT_OK )
    {
        pAttribute->pAttributeValue = &( pCtx->pStart[ pCtx->currentIndex + STUN_ATTRIBUTE_HEADER_VALUE_OFFSET ] );

        pCtx->currentIndex += STUN_ATTRIBUTE_TOTAL_LENGTH( STUN_ALIGN_SIZE_TO_WORD( pAttribute->attributeValueLength ) );
    }

    return result;
}
/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_ParseAttributeErrorCode( const StunAttribute_t * pAttribute,
                                                       uint16_t * errorCode,
                                                       char ** errorPhrase )
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

        *errorCode = STUN_GET_ERROR( class,
                                     errorNumber );
        *errorPhrase = ( uint8_t * ) &( pAttribute->pAttributeValue[STUN_ERROR_CODE_PACKET_ERROR_PHRASE_OFFSET] );
    }
    return result;
}

/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_ParseAttributeChannelNumber( const StunContext_t * pCtx,
                                                           const StunAttribute_t * pAttribute,
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
        STUN_READ_UINT16( channelNumber, ( uint8_t * ) &( *( ( uint16_t * ) pAttribute->pAttributeValue ) ) );
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
        pCtx->attributeFlag |= STUN_FLAG_USE_CANDIDATE_ATTRIBUTE;
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
        pCtx->attributeFlag |= STUN_FLAG_DONT_FRAGMENT_ATTRIBUTE;
    }

    return result;
}
/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_ParseAttributePriority( const StunContext_t * pCtx,
                                                      const StunAttribute_t * pAttribute,
                                                      uint32_t * pPriority )
{
    return StunDeserializer_ParseAttributeUINT32( pCtx,
                                                  pAttribute,
                                                  pPriority,
                                                  STUN_ATTRIBUTE_TYPE_PRIORITY );
}
/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_ParseAttributeFingerpint( const StunContext_t * pCtx,
                                                        const StunAttribute_t * pAttribute,
                                                        uint32_t * pCrc32Fingerprint )
{
    return StunDeserializer_ParseAttributeUINT32( pCtx,
                                                  pAttribute,
                                                  pCrc32Fingerprint,
                                                  STUN_ATTRIBUTE_TYPE_FINGERPRINT );
}
/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_ParseAttributeLifetime( const StunContext_t * pCtx,
                                                      const StunAttribute_t * pAttribute,
                                                      uint32_t * pLifetime )
{
    return StunDeserializer_ParseAttributeUINT32( pCtx,
                                                  pAttribute,
                                                  pLifetime,
                                                  STUN_ATTRIBUTE_TYPE_LIFETIME );
}
/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_ParseAttributeChangeRequest( const StunContext_t * pCtx,
                                                           const StunAttribute_t * pAttribute,
                                                           uint32_t * pChangeFlag )
{
    return StunDeserializer_ParseAttributeUINT32( pCtx,
                                                  pAttribute,
                                                  pChangeFlag,
                                                  STUN_ATTRIBUTE_TYPE_CHANGE_REQUEST );
}
/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_ParseAttributeIceControlled( const StunContext_t * pCtx,
                                                           const StunAttribute_t * pAttribute,
                                                           uint64_t * pTieBreaker )
{
    return StunDeserializer_ParseAttributeUINT64( pCtx,
                                                  pAttribute,
                                                  pTieBreaker,
                                                  STUN_ATTRIBUTE_TYPE_ICE_CONTROLLED );
}
/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_ParseAttributeIceControlling( const StunContext_t * pCtx,
                                                            const StunAttribute_t * pAttribute,
                                                            uint64_t * pTieBreaker )
{

    return StunDeserializer_ParseAttributeUINT64( pCtx,
                                                  pAttribute,
                                                  pTieBreaker,
                                                  STUN_ATTRIBUTE_TYPE_ICE_CONTROLLING );
}
/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_ParseAttributeUsername( const StunAttribute_t * pAttribute,
                                                      const char ** ppUsername,
                                                      uint16_t * pUsernameLength )
{
    return StunDeserializer_ParseAttributeBuffer( pAttribute,
                                                  ppUsername,
                                                  pUsernameLength,
                                                  STUN_ATTRIBUTE_TYPE_USERNAME );
}
/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_ParseAttributeData( const StunAttribute_t * pAttribute,
                                                  const char ** ppData,
                                                  uint16_t * pDataLength )
{
    return StunDeserializer_ParseAttributeBuffer( pAttribute,
                                                  ppData,
                                                  pDataLength,
                                                  STUN_ATTRIBUTE_TYPE_DATA );
}
/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_ParseAttributeRealm( const StunAttribute_t * pAttribute,
                                                   const char ** ppRealm,
                                                   uint16_t * pRealmLength )
{
    return StunDeserializer_ParseAttributeBuffer( pAttribute,
                                                  ppRealm,
                                                  pRealmLength,
                                                  STUN_ATTRIBUTE_TYPE_REALM );
}
/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_ParseAttributeNonce( const StunAttribute_t * pAttribute,
                                                   const char ** ppNonce,
                                                   uint16_t * pNonceLength )
{
    return StunDeserializer_ParseAttributeBuffer( pAttribute,
                                                  ppNonce,
                                                  pNonceLength,
                                                  STUN_ATTRIBUTE_TYPE_NONCE );
}

/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_ParseAttributeRequestedTransport( const StunAttribute_t * pAttribute,
                                                                const char ** ppRequestedTransport,
                                                                uint16_t * pRequestedTransportLength )
{
    return StunDeserializer_ParseAttributeBuffer( pAttribute,
                                                  ppRequestedTransport,
                                                  pRequestedTransportLength,
                                                  STUN_ATTRIBUTE_TYPE_REQUESTED_TRANSPORT );
}
/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_ParseAttributeIntegrity( const StunAttribute_t * pAttribute,
                                                       const char ** ppIntegrity,
                                                       uint16_t * pIntegrityLength )
{
    return StunDeserializer_ParseAttributeBuffer( pAttribute,
                                                  ppIntegrity,
                                                  pIntegrityLength,
                                                  STUN_ATTRIBUTE_TYPE_MESSAGE_INTEGRITY );
}
/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_ParseAttributeAddress( const StunContext_t * pCtx,
                                                     const StunAttribute_t * pAttribute,
                                                     StunAttributeAddress_t * pStunMappedAddress,
                                                     uint8_t * pTransactionId,
                                                     StunAttributeType_t attributeType )
{
    StunResult_t result = STUN_RESULT_OK;
    uint32_t magic = (uint32_t)( STUN_HEADER_MAGIC_COOKIE );
    uint16_t msbMAGIC, port;
    uint8_t *pData, i;
    uint32_t data;

    if( ( pAttribute == NULL ) ||
        ( pAttribute->pAttributeValue == NULL ) ||
        ( pAttribute->attributeType != attributeType ||
        ( pStunMappedAddress == NULL )) )
    {
        result = STUN_RESULT_BAD_PARAM;
    }

    if( result == STUN_RESULT_OK )
    {
        memcpy(pStunMappedAddress, pAttribute->pAttributeValue, pAttribute->attributeValueLength);
        STUN_READ_UINT16( &( pStunMappedAddress->family ),
                          ( uint8_t * ) &pStunMappedAddress->family );

        if( attributeType == STUN_ATTRIBUTE_TYPE_XOR_MAPPED_ADDRESS ||
            attributeType == STUN_ATTRIBUTE_TYPE_XOR_RELAYED_ADDRESS ||
            attributeType == STUN_ATTRIBUTE_TYPE_XOR_PEER_ADDRESS )
        {
            // XOR the port with high-bits of the magic cookie
            STUN_READ_UINT32( &magic, ( uint8_t * ) &magic );
            msbMAGIC = (uint16_t )magic;
            pStunMappedAddress->port ^= msbMAGIC;

            //Calculate XORed address
            STUN_READ_UINT32( &data, ( uint8_t * ) &pStunMappedAddress->address );
            data ^= STUN_HEADER_MAGIC_COOKIE;
            STUN_WRITE_UINT32( ( uint8_t * ) &pStunMappedAddress->address, data );

            if ( pStunMappedAddress->family == STUN_ADDRESS_IPv6 )
            {
                // Process the rest of 12 bytes
                pData = &pStunMappedAddress->address[ STUN_IPV4_ADDRESS_SIZE ];
                for (i = 0; i < STUN_HEADER_TRANSACTION_ID_LENGTH; i++)
                {
                    *pData++ ^= *pTransactionId++;
                }
            }
        }
    }

    return result;
}
/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_ParseAttributeMappedAddress( const StunContext_t * pCtx,
                                                           const StunAttribute_t * pAttribute,
                                                           StunAttributeAddress_t * pStunMappedAddress,
                                                           uint8_t * pTransactionId )
{
    return StunDeserializer_ParseAttributeAddress( pCtx,
                                                   pAttribute,
                                                   pStunMappedAddress,
                                                   pTransactionId,
                                                   STUN_ATTRIBUTE_TYPE_MAPPED_ADDRESS );
}
/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_ParseAttributeResponseAddress( const StunContext_t * pCtx,
                                                             const StunAttribute_t * pAttribute,
                                                             StunAttributeAddress_t * pStunMappedAddress,
                                                             uint8_t * pTransactionId )
{
    return StunDeserializer_ParseAttributeAddress( pCtx,
                                                   pAttribute,
                                                   pStunMappedAddress,
                                                   pTransactionId,
                                                   STUN_ATTRIBUTE_TYPE_RESPONSE_ADDRESS );
}
/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_ParseAttributeSourceAddress( const StunContext_t * pCtx,
                                                           const StunAttribute_t * pAttribute,
                                                           StunAttributeAddress_t * pStunMappedAddress,
                                                           uint8_t * pTransactionId )
{
    return StunDeserializer_ParseAttributeAddress( pCtx,
                                                   pAttribute,
                                                   pStunMappedAddress,
                                                   pTransactionId,
                                                   STUN_ATTRIBUTE_TYPE_SOURCE_ADDRESS );
}
/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_ParseAttributeChangedAddress( const StunContext_t * pCtx,
                                                            const StunAttribute_t * pAttribute,
                                                            StunAttributeAddress_t * pStunMappedAddress,
                                                            uint8_t * pTransactionId )
{
    return StunDeserializer_ParseAttributeAddress( pCtx,
                                                   pAttribute,
                                                   pStunMappedAddress,
                                                   pTransactionId,
                                                   STUN_ATTRIBUTE_TYPE_CHANGED_ADDRESS );
}
/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_ParseAttributeReflectedFrom( const StunContext_t * pCtx,
                                                           const StunAttribute_t * pAttribute,
                                                           StunAttributeAddress_t * pStunMappedAddress,
                                                           uint8_t * pTransactionId )
{
    return StunDeserializer_ParseAttributeAddress( pCtx,
                                                   pAttribute,
                                                   pStunMappedAddress,
                                                   pTransactionId,
                                                   STUN_ATTRIBUTE_TYPE_REFLECTED_FROM );
}
/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_ParseAttributeXORMappedAddress( const StunContext_t * pCtx,
                                                              const StunAttribute_t * pAttribute,
                                                              StunAttributeAddress_t * pStunMappedAddress,
                                                              uint8_t * pTransactionId )
{
    return StunDeserializer_ParseAttributeAddress( pCtx,
                                                   pAttribute,
                                                   pStunMappedAddress,
                                                   pTransactionId,
                                                   STUN_ATTRIBUTE_TYPE_XOR_MAPPED_ADDRESS );
}
/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_ParseAttributeXORPeerAddress( const StunContext_t * pCtx,
                                                            const StunAttribute_t * pAttribute,
                                                            StunAttributeAddress_t * pStunMappedAddress,
                                                            uint8_t * pTransactionId )
{
    return StunDeserializer_ParseAttributeAddress( pCtx,
                                                   pAttribute,
                                                   pStunMappedAddress,
                                                   pTransactionId,
                                                   STUN_ATTRIBUTE_TYPE_XOR_PEER_ADDRESS );
}
/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_ParseAttributeXORRelayedAddress( const StunContext_t * pCtx,
                                                               const StunAttribute_t * pAttribute,
                                                               StunAttributeAddress_t * pStunMappedAddress,
                                                               uint8_t * pTransactionId )
{
    return StunDeserializer_ParseAttributeAddress( pCtx,
                                                   pAttribute,
                                                   pStunMappedAddress,
                                                   pTransactionId,
                                                   STUN_ATTRIBUTE_TYPE_XOR_RELAYED_ADDRESS );
}
/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_IsFlagAttributeFound( const StunContext_t * pCtx,
                                                    StunAttributeType_t attributeType,
                                                    uint16_t * pAttrFound )
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
        if( ( pCtx->attributeFlag & attributeType ) == 1 )
        {
            *pAttrFound = 1;
        }
    }
}
/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_GetIntegrityBuffer( StunContext_t * pCtx,
                                                  char ** ppStunMessage,
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
        STUN_WRITE_UINT16( ( uint8_t * ) &( pCtx->pStart[ STUN_HEADER_MESSAGE_LENGTH_OFFSET ] ),
                           pCtx->currentIndex - STUN_HEADER_LENGTH );

        *ppStunMessage =  (char *) (pCtx->pStart);

        *pStunMessageLength = pCtx->currentIndex - STUN_ATTRIBUTE_TOTAL_LENGTH( STUN_HMAC_VALUE_LENGTH );
    }

    return result;
}
/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_GetFingerprintBuffer( StunContext_t * pCtx,
                                                    char ** ppStunMessage,
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
            STUN_WRITE_UINT16( ( uint8_t * ) &( pCtx->pStart[ STUN_HEADER_MESSAGE_LENGTH_OFFSET ] ),
                                pCtx->currentIndex - STUN_HEADER_LENGTH );

            *ppStunMessage =  (char *) (pCtx->pStart);
        }

        *pStunMessageLength = pCtx->currentIndex - STUN_ATTRIBUTE_TOTAL_LENGTH( STUN_ATTRIBUTE_FINGERPRINT_LENGTH );
    }

    return result;
}
/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_FindAttribute( StunContext_t * pCtx,
                                             char ** ppAttribute,
                                             StunAttributeType_t attributeType )
{
    StunResult_t result = STUN_RESULT_OK;
    StunAttributeType_t foundAttributeType;
    const char *pAttributeBuffer;
    uint16_t msgLen, currentAttrIndex = 0;
    uint16_t attributeFound = 0;
    uint16_t readAttributeType, readAttributeValueLength;

    if( ( pCtx == NULL ) ||
        ( pCtx->pStart == NULL ) )
    {
        result = STUN_RESULT_BAD_PARAM;
    }

    if( result == STUN_RESULT_OK )
    {
        pAttributeBuffer = &(pCtx->pStart[STUN_HEADER_LENGTH]);
        msgLen = pCtx->totalLength;

        if( msgLen == 0 ||
            pAttributeBuffer == NULL )
        {
            //No attributes present;
            result = STATUS_NO_ATTRIBUTE_FOUND;
        }
    }

    if( result == STUN_RESULT_OK )
    {
        while( currentAttrIndex + STUN_ATTRIBUTE_HEADER_LENGTH <= msgLen)
        {
            STUN_READ_UINT16( ( uint16_t * ) &( readAttributeType ),
                              ( uint8_t * ) &( pAttributeBuffer[ currentAttrIndex ] ) );

            /* Read attribute length. */
            STUN_READ_UINT16( &( readAttributeValueLength ),
                              ( uint8_t * ) &( pAttributeBuffer[ currentAttrIndex + STUN_ATTRIBUTE_HEADER_LENGTH_OFFSET ] ) );

            if( attributeType == (StunAttributeType_t) readAttributeType )
            {
                *ppAttribute = (char *)&( pAttributeBuffer[ currentAttrIndex ] );
                attributeFound = 1;
                break;
            }
            currentAttrIndex += STUN_ATTRIBUTE_HEADER_LENGTH + STUN_ALIGN_SIZE_TO_WORD( readAttributeValueLength );
        }
    }

    if( attributeFound == 0 )
    {
        result = STATUS_NO_ATTRIBUTE_FOUND;
    }

    return result;
}
/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_UpdateAttributeNonce( const StunContext_t * pCtx,
                                                    char * pAttribute,
                                                    const char * pNonce,
                                                    uint16_t nonceLength )
{
    StunResult_t result = STUN_RESULT_OK;
    uint16_t length;

    if( ( pAttribute == NULL ) ||
        ( pNonce == NULL ) )
    {
        result = STUN_RESULT_BAD_PARAM;
    }

    if( result == STUN_RESULT_OK )
    {
        STUN_READ_UINT16( &( length ),
                          ( uint8_t * ) &( pAttribute[ STUN_ATTRIBUTE_HEADER_LENGTH_OFFSET ] ) );

        if( length != nonceLength )
        {
            result = STUN_RESULT_BAD_PARAM;
        }
    }

    if( result == STUN_RESULT_OK )
    {
        memcpy( ( void * ) &( pAttribute[ STUN_ATTRIBUTE_HEADER_VALUE_OFFSET ]), pNonce, nonceLength );
    }

    return result;
}

/*-----------------------------------------------------------*/