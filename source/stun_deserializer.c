/* Standard includes. */
#include <stdio.h>
#include <string.h>

/* API includes. */
#include "stun_deserializer.h"

/* Read/Write macros. */
#define STUN_WRITE_UINT16   ( pCtx->readWriteFunctions.writeUint16Fn )
#define STUN_WRITE_UINT32   ( pCtx->readWriteFunctions.writeUint32Fn )
#define STUN_WRITE_UINT64   ( pCtx->readWriteFunctions.writeUint64Fn )
#define STUN_READ_UINT16    ( pCtx->readWriteFunctions.readUint16Fn )
#define STUN_READ_UINT32    ( pCtx->readWriteFunctions.readUint32Fn )
#define STUN_READ_UINT64    ( pCtx->readWriteFunctions.readUint64Fn )

/*-----------------------------------------------------------*/

/* Static Functions. */
static StunResult_t ParseAttributeUint32( const StunContext_t * pCtx,
                                          const StunAttribute_t * pAttribute,
                                          uint32_t * pVal,
                                          StunAttributeType_t attributeType );

static StunResult_t ParseAttributeUint64( const StunContext_t * pCtx,
                                          const StunAttribute_t * pAttribute,
                                          uint64_t * pVal,
                                          StunAttributeType_t attributeType );

/*-----------------------------------------------------------*/

static StunResult_t ParseAttributeUint32( const StunContext_t * pCtx,
                                          const StunAttribute_t * pAttribute,
                                          uint32_t * pVal,
                                          StunAttributeType_t attributeType )
{
    StunResult_t result = STUN_RESULT_OK;

    if( ( pAttribute == NULL ) ||
        ( pVal == NULL ) ||
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
        *pVal = STUN_READ_UINT32( &( pAttribute->pAttributeValue[ 0 ] ) );
    }

    return result;
}

/*-----------------------------------------------------------*/

static StunResult_t ParseAttributeUint64( const StunContext_t * pCtx,
                                          const StunAttribute_t * pAttribute,
                                          uint64_t * pVal,
                                          StunAttributeType_t attributeType )
{
    StunResult_t result = STUN_RESULT_OK;

    if( ( pAttribute == NULL ) ||
        ( pVal == NULL ) ||
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
        *pVal = STUN_READ_UINT64( &( pAttribute->pAttributeValue[ 0 ] ) );
    }

    return result;
}

/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_Init( StunContext_t * pCtx,
                                    uint8_t * pStunMessage,
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
        Stun_InitReadWriteFunctions( &( pCtx->readWriteFunctions ) );

        pCtx->pStart = pStunMessage;
        pCtx->totalLength = stunMessageLength;
        pCtx->currentIndex = 0;
        pCtx->attributeFlag = 0;

        pStunHeader->messageType = STUN_READ_UINT16( &( pCtx->pStart[ pCtx->currentIndex ] ) );
        messageLengthInHeader = STUN_READ_UINT16( &( pCtx->pStart[ pCtx->currentIndex + STUN_HEADER_MESSAGE_LENGTH_OFFSET ] ) );
        magicCookie = STUN_READ_UINT32( &( pCtx->pStart[ pCtx->currentIndex + STUN_HEADER_MAGIC_COOKIE_OFFSET ] ) );

        if( magicCookie != STUN_HEADER_MAGIC_COOKIE )
        {
            result = STUN_RESULT_MAGIC_COOKIE_MISMATCH;
        }
        else if( ( messageLengthInHeader + STUN_HEADER_LENGTH ) != stunMessageLength )
        {
            result = STUN_RESULT_INVALID_MESSAGE_LENGTH;
        }
        else
        {
            pStunHeader->pTransactionId = ( uint8_t * )&( pCtx->pStart[ pCtx->currentIndex +
                                                                        STUN_HEADER_TRANSACTION_ID_OFFSET ] );
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
        pAttribute->attributeType = ( StunAttributeType_t ) STUN_READ_UINT16( &( pCtx->pStart[ pCtx->currentIndex ] ) );

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
            /* No attribute other than Fingerprint can be present after
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
        pAttribute->attributeValueLength = STUN_READ_UINT16( &( pCtx->pStart[ pCtx->currentIndex +
                                                                              STUN_ATTRIBUTE_HEADER_LENGTH_OFFSET ] ) );

        /* Check that we have enough data to read attribute value. */
        if( STUN_REMAINING_LENGTH( pCtx ) < STUN_ATTRIBUTE_TOTAL_LENGTH( pAttribute->attributeValueLength ) )
        {
            result = STUN_RESULT_OUT_OF_MEMORY;
        }
    }

    if( result == STUN_RESULT_OK )
    {
        if( pAttribute->attributeValueLength > 0 )
        {
            pAttribute->pAttributeValue = &( pCtx->pStart[ pCtx->currentIndex +
                                                           STUN_ATTRIBUTE_HEADER_VALUE_OFFSET ] );
        }
        else
        {
            pAttribute->pAttributeValue = NULL;
        }

        pCtx->currentIndex += STUN_ATTRIBUTE_TOTAL_LENGTH( STUN_ALIGN_SIZE_TO_WORD( pAttribute->attributeValueLength ) );
    }

    return result;
}

/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_ParseAttributeErrorCode( const StunAttribute_t * pAttribute,
                                                       uint16_t * pErrorCode,
                                                       uint8_t ** ppErrorPhrase,
                                                       uint16_t * pErrorPhraseLength )
{
    StunResult_t result = STUN_RESULT_OK;
    uint8_t errorClass, errorNumber;
    uint16_t errorPhaseLength = pAttribute->attributeValueLength - STUN_ATTRIBUTE_ERROR_CODE_HEADER_LENGTH;

    if( ( pAttribute == NULL ) ||
        ( pErrorCode == NULL ) ||
        ( pAttribute->pAttributeValue == NULL ) ||
        ( errorPhaseLength <= 0 ) ||
        ( pAttribute->attributeType != STUN_ATTRIBUTE_TYPE_ERROR_CODE ) )
    {
        result = STUN_RESULT_BAD_PARAM;
    }

    if( result == STUN_RESULT_OK )
    {
        errorClass = pAttribute->pAttributeValue[ STUN_ATTRIBUTE_ERROR_CODE_CLASS_OFFSET ];
        errorNumber = pAttribute->pAttributeValue[ STUN_ATTRIBUTE_ERROR_CODE_NUMBER_OFFSET ];

        *pErrorCode = STUN_GET_ERROR( errorClass, errorNumber );
        *ppErrorPhrase = &( pAttribute->pAttributeValue[ STUN_ATTRIBUTE_ERROR_CODE_REASON_PHRASE_OFFSET ] );
        *pErrorPhraseLength = errorPhaseLength;
    }

    return result;
}

/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_ParseAttributeChannelNumber( const StunContext_t * pCtx,
                                                           const StunAttribute_t * pAttribute,
                                                           uint16_t * pChannelNumber )
{
    StunResult_t result = STUN_RESULT_OK;

    if( ( pAttribute == NULL ) ||
        ( pChannelNumber == NULL ) ||
        ( pAttribute->attributeType != STUN_ATTRIBUTE_TYPE_CHANNEL_NUMBER ) ||
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
        *pChannelNumber = STUN_READ_UINT16( &( pAttribute->pAttributeValue[ 0 ] ) );
    }

    return result;
}

/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_ParseAttributePriority( const StunContext_t * pCtx,
                                                      const StunAttribute_t * pAttribute,
                                                      uint32_t * pPriority )
{
    return ParseAttributeUint32( pCtx,
                                 pAttribute,
                                 pPriority,
                                 STUN_ATTRIBUTE_TYPE_PRIORITY );
}

/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_ParseAttributeFingerprint( const StunContext_t * pCtx,
                                                         const StunAttribute_t * pAttribute,
                                                         uint32_t * pCrc32Fingerprint )
{
    return ParseAttributeUint32( pCtx,
                                 pAttribute,
                                 pCrc32Fingerprint,
                                 STUN_ATTRIBUTE_TYPE_FINGERPRINT );
}

/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_ParseAttributeLifetime( const StunContext_t * pCtx,
                                                      const StunAttribute_t * pAttribute,
                                                      uint32_t * pLifetime )
{
    return ParseAttributeUint32( pCtx,
                                 pAttribute,
                                 pLifetime,
                                 STUN_ATTRIBUTE_TYPE_LIFETIME );
}

/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_ParseAttributeChangeRequest( const StunContext_t * pCtx,
                                                           const StunAttribute_t * pAttribute,
                                                           uint32_t * pChangeFlag )
{
    return ParseAttributeUint32( pCtx,
                                 pAttribute,
                                 pChangeFlag,
                                 STUN_ATTRIBUTE_TYPE_CHANGE_REQUEST );
}

/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_ParseAttributeIceControlled( const StunContext_t * pCtx,
                                                           const StunAttribute_t * pAttribute,
                                                           uint64_t * pIceControlledValue )
{
    return ParseAttributeUint64( pCtx,
                                 pAttribute,
                                 pIceControlledValue,
                                 STUN_ATTRIBUTE_TYPE_ICE_CONTROLLED );
}

/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_ParseAttributeIceControlling( const StunContext_t * pCtx,
                                                            const StunAttribute_t * pAttribute,
                                                            uint64_t * pIceControllingValue )
{

    return ParseAttributeUint64( pCtx,
                                 pAttribute,
                                 pIceControllingValue,
                                 STUN_ATTRIBUTE_TYPE_ICE_CONTROLLING );
}

/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_ParseAttributeAddress( const StunContext_t * pCtx,
                                                     const StunAttribute_t * pAttribute,
                                                     StunAttributeAddress_t * pAddress )
{
    StunResult_t result = STUN_RESULT_OK;
    uint16_t msbMagic = ( STUN_HEADER_MAGIC_COOKIE >> 16 );
    uint32_t word, xorWord, i;
    uint8_t byte, xorByte;

    if( ( pAttribute == NULL ) ||
        ( pAttribute->pAttributeValue == NULL ) ||
        ( pAddress == NULL ) )
    {
        result = STUN_RESULT_BAD_PARAM;
    }

    if( result == STUN_RESULT_OK )
    {
        pAddress->family = STUN_READ_UINT16( &( pAttribute->pAttributeValue[ 0 ] ) );
        pAddress->port = STUN_READ_UINT16( &( pAttribute->pAttributeValue[ STUN_ATTRIBUTE_ADDRESS_PORT_OFFSET ] ) );

        memcpy( ( void * ) &( pAddress->address[ 0 ] ),
                ( const void * ) &( pAttribute->pAttributeValue[ STUN_ATTRIBUTE_ADDRESS_IP_ADDRESS_OFFSET ] ),
                pAttribute->attributeValueLength - STUN_ATTRIBUTE_ADDRESS_HEADER_LENGTH );

        if( ( pAttribute->attributeType == STUN_ATTRIBUTE_TYPE_XOR_MAPPED_ADDRESS ) ||
            ( pAttribute->attributeType == STUN_ATTRIBUTE_TYPE_XOR_RELAYED_ADDRESS ) ||
            ( pAttribute->attributeType == STUN_ATTRIBUTE_TYPE_XOR_PEER_ADDRESS ) )
        {
            /* XOR the port with high-bits of the magic cookie. */
            pAddress->port = msbMagic ^ pAddress->port;

            /* XOR first 4 bytes of IP address with magic cookie. */
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
    }

    return result;
}

/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_GetIntegrityBuffer( StunContext_t * pCtx,
                                                  uint8_t ** ppStunMessage,
                                                  uint16_t * pStunMessageLength )
{
    StunResult_t result = STUN_RESULT_OK;

    if( ( pCtx == NULL ) ||
        ( ppStunMessage == NULL ) ||
        ( pStunMessageLength == NULL ) )
    {
        result = STUN_RESULT_BAD_PARAM;
    }

    if( result == STUN_RESULT_OK )
    {
        STUN_WRITE_UINT16( &( pCtx->pStart[ STUN_HEADER_MESSAGE_LENGTH_OFFSET ] ),
                           pCtx->currentIndex - STUN_HEADER_LENGTH );

        *ppStunMessage = pCtx->pStart;
        *pStunMessageLength = pCtx->currentIndex - STUN_ATTRIBUTE_TOTAL_LENGTH( STUN_HMAC_VALUE_LENGTH );
    }

    return result;
}

/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_GetFingerprintBuffer( StunContext_t * pCtx,
                                                    uint8_t ** ppStunMessage,
                                                    uint16_t * pStunMessageLength )
{
    StunResult_t result = STUN_RESULT_OK;

    if( ( pCtx == NULL ) ||
        ( ppStunMessage == NULL ) ||
        ( pStunMessageLength == NULL ) )
    {
        result = STUN_RESULT_BAD_PARAM;
    }

    if( result == STUN_RESULT_OK )
    {
        STUN_WRITE_UINT16( &( pCtx->pStart[ STUN_HEADER_MESSAGE_LENGTH_OFFSET ] ),
                           pCtx->currentIndex - STUN_HEADER_LENGTH );

        *ppStunMessage = pCtx->pStart;
        *pStunMessageLength = pCtx->currentIndex - STUN_ATTRIBUTE_TOTAL_LENGTH( STUN_ATTRIBUTE_FINGERPRINT_LENGTH );
    }

    return result;
}

/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_FindAttribute( StunContext_t * pCtx,
                                             StunAttributeType_t attributeType,
                                             StunAttribute_t * pAttribute )
{
    StunResult_t result = STUN_RESULT_OK;
    StunContext_t localCtx;
    StunHeader_t localHeader;

    if( ( pCtx == NULL ) ||
        ( pCtx->pStart == NULL ) ||
        ( pAttribute == NULL ) )
    {
        result = STUN_RESULT_BAD_PARAM;
    }

    if( result == STUN_RESULT_OK )
    {
        result = StunDeserializer_Init( &( localCtx ),
                                        pCtx->pStart,
                                        pCtx->totalLength,
                                        &( localHeader ) );
    }

    if( result == STUN_RESULT_OK )
    {
        do
        {
            result = StunDeserializer_GetNextAttribute( &( localCtx ),
                                                        pAttribute );

            if( pAttribute->attributeType == attributeType )
            {
                break;
            }
        } while( result == STUN_RESULT_OK );

        /* Set the return code to STUN_RESULT_NO_ATTRIBUTE_FOUND, if we do not
         * find the attribute after iterating over all the attributes. */
        if( result == STUN_RESULT_NO_MORE_ATTRIBUTE_FOUND )
        {
            result = STUN_RESULT_NO_ATTRIBUTE_FOUND;
        }
    }

    return result;
}

/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_UpdateAttributeNonce( const StunContext_t * pCtx,
                                                    const char * pNonce,
                                                    uint16_t nonceLength,
                                                    StunAttribute_t * pAttribute )
{
    StunResult_t result = STUN_RESULT_OK;
    uint16_t length;

    if( ( pAttribute == NULL ) ||
        ( pNonce == NULL ) ||
        ( pAttribute->attributeType != STUN_ATTRIBUTE_TYPE_NONCE ) ||
        ( pAttribute->attributeValueLength != nonceLength ) )
    {
        result = STUN_RESULT_BAD_PARAM;
    }

    if( result == STUN_RESULT_OK )
    {
        memcpy( ( void * ) &( pAttribute->pAttributeValue[ 0 ] ),
                ( const void * ) pNonce,
                nonceLength );
    }

    return result;
}

/*-----------------------------------------------------------*/
