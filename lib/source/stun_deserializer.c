/* Standard includes. */
#include <stdio.h>
#include <string.h>

/* API includes. */
#include "stun_deserializer.h"

StunResult_t StunDeserializer_Init( StunContext_t * pCtx,
                                    const uint8_t * pStunMessage,
                                    size_t stunMessageLength )
{
    StunResult_t result = STUN_RESULT_OK;

    if( ( pCtx == NULL ) ||
        ( pStunMessage == NULL ) ||
        ( stunMessageLength < STUN_HEADER_LENGTH ) )
    {
        result = STUN_RESULT_BAD_PARAM;
    }

    if( result == STUN_RESULT_OK )
    {
        pCtx->pStart = pStunMessage;
        pCtx->totalLength = stunMessageLength;
        pCtx->currentIndex = 0;
        pCtx->flags = 0;
    }

    return result;
}
/*-----------------------------------------------------------*/

StunResult_t StunDeserializer_GetHeader( StunContext_t * pCtx,
                                         StunHeader_t * pStunHeader )
{
    StunResult_t result = STUN_RESULT_OK;
    uint32_t magicCookie;

    if( ( pCtx == NULL ) ||
        ( pStunHeader == NULL ) ||
        ( pCtx->currentIndex != 0 ) )
    {
        result = STUN_RESULT_BAD_PARAM;
    }

    if( result == STUN_RESULT_OK )
    {
        if( REMAINING_LENGTH( pCtx ) < STUN_HEADER_LENGTH )
        {
            result = STUN_RESULT_MALFORMED_MESSAGE;
        }
    }

    if( result == STUN_RESULT_OK )
    {
        READ_UINT16( pStunHeader->messageType,
                     &( pCtx->pStart[ pCtx->currentIndex ] ) );
        READ_UINT16( pStunHeader->messageLength,
                     &( pCtx->pStart[ pCtx->currentIndex + STUN_HEADER_MESSAGE_LENGTH_OFFSET ] ) );
        READ_UINT32( magicCookie,
                     &( pCtx->pStart[ pCtx->currentIndex + STUN_HEADER_MAGIC_COOKIE_OFFSET ] ) );

        if( magicCookie != STUN_HEADER_MAGIC_COOKIE )
        {
            result = STUN_RESULT_MAGIC_COOKIE_MISMATCH;
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
    uint32_t isSeenFingerprint, isSeenIntegrity;

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
        isSeenFingerprint = STUN_FLAG_FINGERPRINT_ATTRIBUTE_SEEN( pCtx->flags );
        isSeenIntegrity = STUN_FLAG_INTEGRITY_ATTRIBUTE_SEEN( pCtx->flags );

        if( isSeenFingerprint )
        {
            /* No more attributes can be added, Fingerprint should be the last */
            result = STUN_RESULT_INVALID_ATTRIBUTE_ORDER;
        }
        else if( isSeenIntegrity && pAttribute->attributeType != STUN_ATTRIBUTE_TYPE_FINGERPRINT )
        {
            /* No attribute other than fingerprint can be added after Inegrity attribute*/
            result = STUN_RESULT_INVALID_ATTRIBUTE_ORDER;
        }
    }

    if( result == STUN_RESULT_OK )
    {
        /* Update flags. */
        if( pAttribute->attributeType == STUN_ATTRIBUTE_TYPE_FINGERPRINT )
        {
            pCtx->flags |= STUN_FLAG_FINGERPRINT_ATTRIBUTE_UPDATE;
        }
        if( pAttribute->attributeType == STUN_ATTRIBUTE_TYPE_MESSAGE_INTEGRITY )
        {
            pCtx->flags |= STUN_FLAG_INTEGRITY_ATTRIBUTE_UPDATE;
        }

        READ_UINT16( attributeType,
                     &( pCtx->pStart[ pCtx->currentIndex ] ) );
        pAttribute->attributeType = ( StunAttributeType_t ) attributeType;

        READ_UINT16( pAttribute->attributeValueLength,
                     &( pCtx->pStart[ pCtx->currentIndex + STUN_ATTRIBUTE_HEADER_LENGTH_OFFSET ] ) );

        pAttribute->pAttributeValue = (char *) &( pCtx->pStart[ pCtx->currentIndex + STUN_ATTRIBUTE_HEADER_VALUE_OFFSET ] );

        pCtx->currentIndex += STUN_ATTRIBUTE_TOTAL_LENGTH( ALIGN_SIZE_TO_WORD(pAttribute->attributeValueLength) );
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
        READ_UINT32( *pPriority, &( *( ( uint32_t * ) pAttribute->pAttributeValue ) ) );
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
