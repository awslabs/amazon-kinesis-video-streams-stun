/* Unity includes. */
#include "unity.h"
#include "catch_assert.h"

/* Standard includes. */
#include <string.h>
#include <stdint.h>

/* API includes. */
#include "stun_serializer.h"
#include "stun_endianness.h"
#include "stun_data_types.h"

/* ===========================  EXTERN VARIABLES  =========================== */

#define MAX_BUFFER_LENGTH        20

void setUp( void )
{
}

void tearDown( void )
{
}

/* ==============================  Test Cases ============================== */

/**
 * @brief Validate StunSerializer_Init in the happy path.
 */
void test_StunSerializer_Init_Pass( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header;
    uint8_t pBuffer[MAX_BUFFER_LENGTH];
    size_t bufferLength;
    uint8_t transactionId[STUN_HEADER_TRANSACTION_ID_LENGTH] = { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 };

    result = StunSerializer_Init( &( ctx ),
                                  NULL,
                                  0,
                                  &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );

    header.messageType = STUN_MESSAGE_TYPE_BINDING_REQUEST;
    header.pTransactionId = &( transactionId[0] );
    bufferLength = MAX_BUFFER_LENGTH;

    result = StunSerializer_Init( &ctx,
                                  pBuffer,
                                  bufferLength,
                                  &header );

    TEST_ASSERT_EQUAL( STUN_RESULT_OK,
                       result );
    TEST_ASSERT_EQUAL_PTR( pBuffer,
                           ctx.pStart );
    TEST_ASSERT_EQUAL( bufferLength,
                       ctx.totalLength );
    TEST_ASSERT_EQUAL( STUN_HEADER_LENGTH,
                       ctx.currentIndex );
    TEST_ASSERT_EQUAL( 0,
                       ctx.attributeFlag );
    TEST_ASSERT_EQUAL_HEX16( header.messageType,
                             ( pBuffer[0] << 8 ) | pBuffer[1] );
    TEST_ASSERT_EQUAL_HEX16( 0,
                             ( pBuffer[STUN_HEADER_MESSAGE_LENGTH_OFFSET] << 8 ) | pBuffer[STUN_HEADER_MESSAGE_LENGTH_OFFSET + 1] );
    TEST_ASSERT_EQUAL_HEX32( STUN_HEADER_MAGIC_COOKIE,
                             ( pBuffer[STUN_HEADER_MAGIC_COOKIE_OFFSET] << 24 ) | ( pBuffer[STUN_HEADER_MAGIC_COOKIE_OFFSET + 1] << 16 ) | ( pBuffer[STUN_HEADER_MAGIC_COOKIE_OFFSET + 2] << 8 ) | pBuffer[STUN_HEADER_MAGIC_COOKIE_OFFSET + 3] );
    TEST_ASSERT_EQUAL_HEX8_ARRAY( transactionId,
                                  &( pBuffer[STUN_HEADER_TRANSACTION_ID_OFFSET] ),
                                  STUN_HEADER_TRANSACTION_ID_LENGTH );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate StunSerializer_Init incase of bad parameters.
 */
void test_StunSerializer_Init_BadParams( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header;
    uint8_t pBuffer[MAX_BUFFER_LENGTH];
    size_t bufferLength;

    bufferLength = MAX_BUFFER_LENGTH;

    result = StunSerializer_Init( NULL,
                                  &( pBuffer[0] ),
                                  bufferLength,
                                  &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_BAD_PARAM,
                       result );

    bufferLength = MAX_BUFFER_LENGTH;

    result = StunSerializer_Init( &( ctx ),
                                  &( pBuffer[0] ),
                                  bufferLength,
                                  NULL );

    TEST_ASSERT_EQUAL( STUN_RESULT_BAD_PARAM,
                       result );

    bufferLength = 10;

    result = StunSerializer_Init( &( ctx ),
                                  &( pBuffer[0] ),
                                  bufferLength,
                                  &( header ) );

    TEST_ASSERT_EQUAL( STUN_RESULT_BAD_PARAM,
                       result );
}

