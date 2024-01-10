/* Standard includes. */
#include <stdio.h>
#include <string.h>

/* API includes. */
#include "stun_serializer.h"

static StunResult_t AddAttributeBuffer( StunContext_t * pCtx,
                                        StunAttributeType_t attributeType,
                                        const uint8_t * pAttributeValueBuffer,
                                        uint16_t attributeValueBufferLength );

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
    uint16_t attributeValueLengthPadded;

    if( ( pCtx == NULL ) ||
        ( pAttributeValueBuffer == NULL ) ||
        ( attributeValueBufferLength == 0 ) )
    {
        result = STUN_RESULT_BAD_PARAM;
    }

    if( result == STUN_RESULT_OK )
    {
        attributeValueLengthPadded = ALIGN_SIZE_TO_WORD( attributeValueBufferLength );

        if( REMAINING_LENGTH( pCtx ) < STUN_ATTRIBUTE_TOTAL_LENGTH( attributeValueLengthPadded ) )
        {
            result = STUN_RESULT_OUT_OF_MEMORY;
        }
    }

    if( result == STUN_RESULT_OK )
    {
        if( ( pCtx->flags & STUN_FLAG_FINGERPRINT_ATTRIBUTE ) != 0 )
        {
            /* No more attributes can be added after Fingerprint - it must  be
             * the last attribute. */
            result = STUN_RESULT_INVALID_ATTRIBUTE_ORDER;
        }
        else if( ( ( pCtx->flags & STUN_FLAG_INTEGRITY_ATTRIBUTE ) != 0 ) &&
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
            pCtx->flags |= STUN_FLAG_FINGERPRINT_ATTRIBUTE;
        }
        if( attributeType == STUN_ATTRIBUTE_TYPE_MESSAGE_INTEGRITY )
        {
            pCtx->flags |= STUN_FLAG_INTEGRITY_ATTRIBUTE;
        }

        /* Write Attribute type, length and value. */
        WRITE_UINT16( &( pCtx->pStart[ pCtx->currentIndex ] ),
                      attributeType );

        WRITE_UINT16( &( pCtx->pStart[ pCtx->currentIndex + STUN_ATTRIBUTE_HEADER_LENGTH_OFFSET ] ),
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

        pCtx->currentIndex += STUN_ATTRIBUTE_TOTAL_LENGTH( attributeValueLengthPadded );
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

    if( result == STUN_RESULT_OK )
    {
        if( REMAINING_LENGTH( pCtx ) < STUN_ATTRIBUTE_TOTAL_LENGTH( attributeValueLength ) )
        {
            result = STUN_RESULT_OUT_OF_MEMORY;
        }
    }

    if( result == STUN_RESULT_OK )
    {
        if( ( pCtx->flags & STUN_FLAG_FINGERPRINT_ATTRIBUTE ) != 0 )
        {
            /* No more attributes can be added after Fingerprint - it must  be
             * the last attribute. */
            result = STUN_RESULT_INVALID_ATTRIBUTE_ORDER;
        }
        else if( ( ( pCtx->flags & STUN_FLAG_INTEGRITY_ATTRIBUTE ) != 0 ) &&
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
            pCtx->flags |= STUN_FLAG_FINGERPRINT_ATTRIBUTE;
        }
        if( attributeType == STUN_ATTRIBUTE_TYPE_MESSAGE_INTEGRITY )
        {
            pCtx->flags |= STUN_FLAG_INTEGRITY_ATTRIBUTE;
        }

        /* Write Attribute type, length and value. */
        WRITE_UINT16( &( pCtx->pStart[ pCtx->currentIndex ] ),
                      attributeType );

        WRITE_UINT16( &( pCtx->pStart[ pCtx->currentIndex + STUN_ATTRIBUTE_HEADER_LENGTH_OFFSET ] ),
                      attributeValueLength );

        WRITE_UINT32( &( pCtx->pStart[ pCtx->currentIndex + STUN_ATTRIBUTE_HEADER_VALUE_OFFSET ] ),
                      attributeValue );

        pCtx->currentIndex += STUN_ATTRIBUTE_TOTAL_LENGTH( attributeValueLength );
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
        ( pBuffer == NULL ) ||
        ( bufferLength < STUN_HEADER_LENGTH ) ||
        ( pHeader == NULL ) )
    {
        result = STUN_RESULT_BAD_PARAM;
    }

    if( result == STUN_RESULT_OK )
    {
        pCtx->pStart = pBuffer;
        pCtx->totalLength = bufferLength;
        pCtx->currentIndex = 0;
        pCtx->flags = 0;

        WRITE_UINT16( &( pCtx->pStart[ pCtx->currentIndex ] ),
                      pHeader->messageType );

        /* Message length is updated in finalize. */
        WRITE_UINT16( &( pCtx->pStart[ pCtx->currentIndex + STUN_HEADER_MESSAGE_LENGTH_OFFSET ] ),
                      0 );

        WRITE_UINT32( &( pCtx->pStart[ pCtx->currentIndex + STUN_HEADER_MAGIC_COOKIE_OFFSET ] ),
                      STUN_HEADER_MAGIC_COOKIE );

        memcpy( ( void * ) &( pCtx->pStart[ pCtx->currentIndex + STUN_HEADER_TRANSACTION_ID_OFFSET ] ),
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
    return AddAttributeU32( pCtx,
                            STUN_ATTRIBUTE_TYPE_PRIORITY,
                            priority );
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
