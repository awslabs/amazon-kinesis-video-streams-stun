/* Standard includes. */
#include <stdio.h>
#include <string.h>

/* API includes. */
#include "stun_serializer.h"

static StunResult_t AddAttributeGeneric( StunContext_t * pCtx,
                                         const StunAttribute_t * pAttribute );
/*-----------------------------------------------------------*/

static StunResult_t AddAttributeGeneric( StunContext_t * pCtx,
                                         const StunAttribute_t * pAttribute )
{
    StunResult_t result = STUN_RESULT_OK;
    uint16_t attributeLengthPadded;

    if( ( pCtx == NULL ) ||
        ( pAttribute == NULL ) )
    {
        result = STUN_RESULT_BAD_PARAM;
    }

    if( result == STUN_RESULT_OK )
    {
        attributeLengthPadded = ALIGN_SIZE_TO_WORD( pAttribute->attributeValueLength );

        if( REMAINING_LENGTH( pCtx ) < STUN_ATTRIBUTE_TOTAL_LENGTH( attributeLengthPadded ) )
        {
            result = STUN_RESULT_OUT_OF_MEMORY;
        }
    }

    if( result == STUN_RESULT_OK )
    {
        WRITE_UINT16( &( pCtx->pStart[ pCtx->currentIndex ] ),
                      pAttribute->attributeType );

        WRITE_UINT16( &( pCtx->pStart[ pCtx->currentIndex + STUN_ATTRIBUTE_HEADER_LENGTH_OFFSET ] ),
                      pAttribute->attributeValueLength );

        memcpy( &( pCtx->pStart[ pCtx->currentIndex + STUN_ATTRIBUTE_HEADER_VALUE_OFFSET ] ),
                pAttribute->pAttributeValue,
                pAttribute->attributeValueLength );

        /* Zero out the padded bytes. */

        pCtx->currentIndex += STUN_ATTRIBUTE_TOTAL_LENGTH( attributeLengthPadded );
    }

    return result;
}
/*-----------------------------------------------------------*/

StunResult_t StunSerializer_Init( StunContext_t * pCtx,
                                  uint8_t * pBuffer,
                                  size_t bufferLength )
{
    StunResult_t result = STUN_RESULT_OK;

    if( ( pCtx == NULL ) ||
        ( pBuffer == NULL ) ||
        ( bufferLength < STUN_HEADER_LENGTH ) )
    {
        result = STUN_RESULT_BAD_PARAM;
    }

    if( result == STUN_RESULT_OK )
    {
        pCtx->pStart = pBuffer;
        pCtx->totalLength = bufferLength;
        pCtx->currentIndex = 0;
    }

    return result;
}
/*-----------------------------------------------------------*/

StunResult_t StunSerializer_AddHeader( StunContext_t * pCtx,
                                       const StunHeader_t * pHeader )
{
    StunResult_t result = STUN_RESULT_OK;

    if( ( pCtx == NULL ) ||
        ( pHeader == NULL ) )
    {
        result = STUN_RESULT_BAD_PARAM;
    }

    if( result == STUN_RESULT_OK )
    {
        if( REMAINING_LENGTH( pCtx ) < STUN_HEADER_LENGTH )
        {
            result = STUN_RESULT_OUT_OF_MEMORY;
        }
    }

    if( result == STUN_RESULT_OK )
    {
        WRITE_UINT16( &( pCtx->pStart[ pCtx->currentIndex ] ),
                      pHeader->messageType );

        /* Message length is updated in finalize. */
        WRITE_UINT16( &( pCtx->pStart[ pCtx->currentIndex + STUN_HEADER_MESSAGE_LENGTH_OFFSET ] ),
                      0 );

        WRITE_UINT32( &( pCtx->pStart[ pCtx->currentIndex + STUN_HEADER_MAGIC_COOKIE_OFFSET ] ),
                      STUN_HEADER_MAGIC_COOKIE );

        memcpy( &( pCtx->pStart[ pCtx->currentIndex + STUN_HEADER_TRANSACTION_ID_OFFSET ] ),
                &( pHeader->transactionId[ 0 ] ),
                STUN_HEADER_TRANSACTION_ID_LENGTH );

        pCtx->currentIndex += STUN_HEADER_LENGTH;
    }

    return result;
}
/*-----------------------------------------------------------*/

StunResult_t StunSerializer_AddAttributePriority( StunContext_t * pCtx,
                                                  uint32_t priority )
{
    StunResult_t result;
    StunAttribute_t attribute;
    uint32_t priorityUpdated;

    WRITE_UINT32( &priorityUpdated, priority );

    attribute.attributeType = STUN_ATTRIBUTE_TYPE_PRIORITY;
    attribute.pAttributeValue = ( uint8_t * )&( priorityUpdated );
    attribute.attributeValueLength = sizeof( priorityUpdated );

    result = AddAttributeGeneric( pCtx,
                                  &( attribute ) );

    return result;
}
/*-----------------------------------------------------------*/

StunResult_t StunSerializer_AddAttributeUsername( StunContext_t * pCtx,
                                                  const char * pUsername,
                                                  uint16_t usernameLength )
{
    StunResult_t result;
    StunAttribute_t attribute;

    attribute.attributeType = STUN_ATTRIBUTE_TYPE_USERNAME;
    attribute.pAttributeValue = ( uint8_t * ) pUsername;
    attribute.attributeValueLength = usernameLength;

    result = AddAttributeGeneric( pCtx,
                                  &( attribute ) );

    return result;
}

/*-----------------------------------------------------------*/

StunResult_t StunSerializer_Finalize( StunContext_t * pCtx,
                                      const uint8_t ** pStunMessage,
                                      size_t * pStunMessageLength )
{
    StunResult_t result = STUN_RESULT_OK;

    if( ( pCtx == NULL ) ||
        ( pStunMessageLength == NULL ) )
    {
        result = STUN_RESULT_BAD_PARAM;
    }

    if( result == STUN_RESULT_OK )
    {
        /* Perform attribute related checks. */

        /* Update the message length field in the header. */
        WRITE_UINT16( &( pCtx->pStart[ STUN_HEADER_MESSAGE_LENGTH_OFFSET ] ),
                      pCtx->currentIndex - STUN_HEADER_LENGTH );

        if( pStunMessage != NULL )
        {
            *pStunMessage = pCtx->pStart;
        }

        *pStunMessageLength = pCtx->currentIndex;
    }

    return result;
}
/*-----------------------------------------------------------*/
