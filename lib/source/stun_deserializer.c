/* Standard includes. */
#include <stdio.h>
#include <string.h>

/* API includes. */
#include "stun_deserializer.h"

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

StunResult_t StunDeserializer_ParseAttributePriority( const StunAttribute_t * pAttribute,
                                                      uint32_t * pPriority )
{
    StunResult_t result = STUN_RESULT_OK;

    if( ( pAttribute == NULL ) ||
        ( pPriority == NULL ) ||
        ( pAttribute->pAttributeValue == NULL ) ||
        ( pAttribute->attributeType != STUN_ATTRIBUTE_TYPE_PRIORITY ) )
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
        READ_UINT32( pPriority, (uint8_t *) &( *( ( uint32_t * ) pAttribute->pAttributeValue ) ) );
    }

    return result;
}
/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_ParseAttributeUsername( const StunAttribute_t * pAttribute,
                                                      const char ** pUsername,
                                                      uint16_t * pUsernameLength )
{
    StunResult_t result = STUN_RESULT_OK;

    if( ( pAttribute == NULL ) ||
        ( pUsernameLength == NULL ) ||
        ( pAttribute->pAttributeValue == NULL ) ||
        ( pAttribute->attributeType != STUN_ATTRIBUTE_TYPE_USERNAME ) )
    {
        result = STUN_RESULT_BAD_PARAM;
    }

    if( result == STUN_RESULT_OK )
    {
        *pUsername = ( const char * ) pAttribute->pAttributeValue;
        *pUsernameLength = pAttribute->attributeValueLength;
    }

    return result;
}
/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_ParseAttributeAddress( const StunAttribute_t * pAttribute,
                                                           StunAttributeAddress_t **pStunMappedAddress )
{
    StunResult_t result = STUN_RESULT_OK;

     if( ( pAttribute == NULL ) ||
        ( pAttribute->pAttributeValue == NULL ) ||
        ( pAttribute->attributeType != STUN_ATTRIBUTE_TYPE_MAPPED_ADDRESS ) )
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

StunResult_t StunDeserializer_ParseAttributeXORAddress( const StunAttribute_t * pAttribute,
                                                        StunAttributeAddress_t **pStunMappedAddress,
                                                        uint8_t *pTransactionId )
{
    StunResult_t result = STUN_RESULT_OK;
    uint16_t msbMAGIC = (STUN_HEADER_MAGIC_COOKIE >> 16);
    uint16_t port;
    StunAttributeAddress_t *pXorAddress;
    uint8_t *pData, i;
    uint32_t data;

    if( ( pAttribute == NULL ) ||
        ( pAttribute->pAttributeValue == NULL ) ||
        ( pAttribute->attributeType != STUN_ATTRIBUTE_TYPE_XOR_MAPPED_ADDRESS ) )
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
