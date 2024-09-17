/* Unity includes. */
#include "unity.h"
#include "catch_assert.h"

/* Standard includes. */
#include <string.h>
#include <stdint.h>

/* API includes. */
#include "stun_deserializer.h"
#include "stun_endianness.h"
#include "stun_data_types.h"

/* ===========================  EXTERN VARIABLES  =========================== */

#define MAX_MESSAGE_LENGTH        20

void setUp( void )
{
}

void tearDown( void )
{
}

/* ==============================  Test Cases ============================== */

/**
 * @brief Validate Validate StunDeserializer_Init incase of happy path.
 */

void test_StunDeserializer_Init_Pass( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    uint8_t pStunMessage[MAX_MESSAGE_LENGTH];
    size_t stunMessageLength = MAX_MESSAGE_LENGTH;
    uint8_t transactionId[STUN_HEADER_TRANSACTION_ID_LENGTH] = { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 };

    pStunMessage[0] = STUN_MESSAGE_TYPE_BINDING_REQUEST >> 8;
    pStunMessage[1] = STUN_MESSAGE_TYPE_BINDING_REQUEST & 0xFF;
    pStunMessage[2] = 0;
    pStunMessage[3] = 0;
    pStunMessage[4] = STUN_HEADER_MAGIC_COOKIE >> 24;
    pStunMessage[5] = ( STUN_HEADER_MAGIC_COOKIE >> 16 ) & 0xFF;
    pStunMessage[6] = ( STUN_HEADER_MAGIC_COOKIE >> 8 ) & 0xFF;
    pStunMessage[7] = STUN_HEADER_MAGIC_COOKIE & 0xFF;
    memcpy( &pStunMessage[8],
            transactionId,
            STUN_HEADER_TRANSACTION_ID_LENGTH );

    result = StunDeserializer_Init( &( ctx ),
                                    &( pStunMessage[0] ),
                                    stunMessageLength,
                                    &( header ) );

    TEST_ASSERT_EQUAL_INT( STUN_RESULT_OK,
                           result );
    TEST_ASSERT_EQUAL_HEX16( STUN_MESSAGE_TYPE_BINDING_REQUEST,
                             header.messageType );
    TEST_ASSERT_EQUAL_HEX8_ARRAY( transactionId,
                                  header.pTransactionId,
                                  STUN_HEADER_TRANSACTION_ID_LENGTH );
    TEST_ASSERT_EQUAL_PTR( pStunMessage,
                           ctx.pStart );
    TEST_ASSERT_EQUAL( stunMessageLength,
                       ctx.totalLength );
    TEST_ASSERT_EQUAL( STUN_HEADER_LENGTH,
                       ctx.currentIndex );
    TEST_ASSERT_EQUAL( 0,
                       ctx.attributeFlag );
}

/*-----------------------------------------------------------*/

/**
 * @brief Validate Validate StunDeserializer_Init incase of bad parameters.
 */
void test_StunDeserializer_Init_BadParams( void )
{
    StunContext_t ctx = { 0 };
    StunResult_t result;
    StunHeader_t header = { 0 };
    uint8_t pStunMessage[MAX_MESSAGE_LENGTH];
    size_t stunMessageLength;

    stunMessageLength = MAX_MESSAGE_LENGTH;

    result = StunDeserializer_Init( NULL,
                                    &( pStunMessage[0] ),
                                    stunMessageLength,
                                    &( header ) );

    TEST_ASSERT_EQUAL_INT( STUN_RESULT_BAD_PARAM,
                           result );

    stunMessageLength = MAX_MESSAGE_LENGTH;

    result = StunDeserializer_Init( &( ctx ),
                                    NULL,
                                    stunMessageLength,
                                    &( header ) );

    TEST_ASSERT_EQUAL_INT( STUN_RESULT_BAD_PARAM,
                           result );

    stunMessageLength = 10;

    result = StunDeserializer_Init( &( ctx ),
                                    &( pStunMessage[0] ),
                                    stunMessageLength,
                                    &( header ) );

    TEST_ASSERT_EQUAL_INT( STUN_RESULT_BAD_PARAM,
                           result );

    stunMessageLength = MAX_MESSAGE_LENGTH;

    result = StunDeserializer_Init( &( ctx ),
                                    &( pStunMessage[0] ),
                                    stunMessageLength,
                                    NULL );

    TEST_ASSERT_EQUAL_INT( STUN_RESULT_BAD_PARAM,
                           result );

}

